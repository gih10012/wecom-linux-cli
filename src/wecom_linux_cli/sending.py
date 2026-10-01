"""Exactly-once dispatch attempts through the owner's running native client.

Request journals are durable before the hook can enter native sending code.
Uncertain results are queried, never automatically resubmitted. Authorization
belongs to the calling agent: this module has no recipient allowlist.
"""

import fcntl
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import struct
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from . import client, keys
from .content import decode
from .database import open_snapshot
from .messages import account, names
from .state import private_root, read_private, write_private

SUPPORTED_SHA256 = "ca7280999c0ae011bf2fac296c24f796595f3558df784edc50dd3f9a6edac5d9"
REQUEST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{3,79}\Z")
CHAT = re.compile(r"[A-Za-z0-9_:@.-]{1,255}\Z")
POLICY = "small_module_remains_until_client_exit_for_callback_safety"


def _folder(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("UNSAFE_SEND_DIRECTORY")
    return path


def _journal(request_id: str) -> Path:
    if not REQUEST.fullmatch(request_id):
        raise ValueError("INVALID_REQUEST_ID")
    return _folder(private_root() / "send") / (request_id + ".json")


def _persist(path: Path, value: dict) -> None:
    write_private(path, value)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _lock():
    folder = _folder(private_root() / "send")
    descriptor = os.open(folder / ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("UNSAFE_SEND_LOCK")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def artifacts() -> dict:
    source = Path(__file__).parent / "_native"
    files = ("message_hook.h", "message_hook.c", "message_dispatch.c", "message_resolve.c")
    digest = hashlib.sha256(b"native-message-v2-send-enabled\0" +
                            b"".join((source / name).read_bytes() for name in files)).hexdigest()
    folder = _folder(private_root() / "native" / digest)
    result = {}
    compiler = shutil.which("i686-w64-mingw32-gcc")
    for name, flags in (("message_hook", ["-shared", "-Wl,--kill-at", "-DWECOM_ENABLE_SEND=1"]),
                        ("message_dispatch", ["-municode"]),
                        ("message_resolve", ["-municode"])):
        target = folder / (name + (".dll" if name == "message_hook" else ".exe"))
        if not target.exists():
            if not compiler:
                raise ValueError("MINGW32_COMPILER_REQUIRED")
            descriptor, temporary = tempfile.mkstemp(prefix="build-", suffix=target.suffix, dir=folder)
            os.close(descriptor)
            try:
                built = subprocess.run([compiler, "-O2", "-Wall", "-Wextra", "-Werror",
                                        "-Wno-misleading-indentation", *flags,
                                        str(source / (name + ".c")), "-luser32", "-o", temporary],
                                       capture_output=True, timeout=60)
                if built.returncode:
                    raise ValueError("NATIVE_SEND_BUILD_FAILED_" + name.upper())
                Path(temporary).chmod(0o700)
                os.replace(temporary, target)
            finally:
                Path(temporary).unlink(missing_ok=True)
        info = target.lstat()
        if target.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("UNSAFE_SEND_ARTIFACT")
        result[name] = target
    result["digest"] = digest
    return result


def _winpath(path: Path) -> str:
    return "Z:" + str(path).replace("/", "\\")


def _invoke(arguments: list, env: dict, timeout: int = 30) -> dict:
    completed = subprocess.run(arguments, env=env, capture_output=True, text=True, timeout=timeout)
    lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
    if len(lines) != 1:
        raise ValueError("MISSING_OR_AMBIGUOUS_SEND_HELPER_RESULT")
    result = json.loads(lines[0])
    if completed.returncode and result.get("ok"):
        raise ValueError("INCONSISTENT_SEND_HELPER_RESULT")
    return result


def _prepare(name: str, chat: str, text: str) -> dict:
    if not isinstance(text, str) or not 1 <= len(text.encode("utf-8")) <= 3072 or "\0" in text:
        raise ValueError("TEXT_MUST_BE_1_TO_3072_UTF8_BYTES_WITHOUT_NUL")
    value = account(name)
    if not value["self_id"].isdecimal():
        raise ValueError("INVALID_ACCOUNT_SELF_ID")
    _, chats, _ = names(value)
    if chat not in chats:
        matched = [cid for cid, label in chats.items() if label == chat]
        if len(matched) > 1:
            raise ValueError("AMBIGUOUS_CHAT_NAME_USE_EXACT_ID")
        if matched:
            chat = matched[0]
    if not CHAT.fullmatch(chat):
        raise ValueError("INVALID_CHAT_ID")
    current = client.config()
    if not current.get("prefix") or not current.get("executable"):
        raise ValueError("CLIENT_NOT_CONFIGURED")
    prefix = Path(current["prefix"]).resolve()
    executable = Path(current["executable"]).resolve()
    drive = prefix / "drive_c"
    if not executable.is_relative_to(drive) or not value["data_dir"].resolve().is_relative_to(drive):
        raise ValueError("ACCOUNT_OR_EXECUTABLE_OUTSIDE_CONFIGURED_PREFIX")
    if prefix.stat().st_uid != os.getuid() or prefix.stat().st_mode & 0o077:
        raise ValueError("UNSAFE_WINE_PREFIX")
    with executable.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SUPPORTED_SHA256:
            raise ValueError("UNSUPPORTED_CLIENT_BINARY_NO_NATIVE_CALL")
    before = client.processes(prefix, executable)
    if len(before) != 1:
        raise ValueError("ONE_RUNNING_CLIENT_REQUIRED")
    if (prefix / "dosdevices/z:").resolve() != Path("/"):
        raise ValueError("STANDARD_WINE_Z_MAPPING_REQUIRED")
    wine = shutil.which("wine")
    if not wine:
        raise ValueError("WINE_NOT_INSTALLED")
    env = client.environment(current)
    env["WINEDEBUG"] = "-all"
    desktop = current.get("desktop", "").split(",")[0]
    if desktop and not re.fullmatch(r"[A-Za-z0-9_-]+", desktop):
        raise ValueError("INVALID_DESKTOP_CONFIGURATION")
    env["WECOM_CLI_DESKTOP"] = desktop
    windows_exe = "C:\\" + str(executable.relative_to(drive)).replace("/", "\\")
    probe = keys._result([wine, str(keys.helper()), windows_exe], env)
    built = artifacts()
    resolution = _invoke([wine, str(built["message_resolve"]), windows_exe,
                          str(probe["windows_pid"]), str(probe["creation_filetime"]),
                          desktop or "-", value["self_id"]], env)
    if not resolution.get("ok") or client.processes(prefix, executable) != before:
        raise ValueError("SEND_MANAGER_OR_ACCOUNT_NOT_VERIFIED")
    return {"account": name, "value": value, "chat": chat, "text": text, "env": env,
            "wine": wine, "executable": executable, "windows_exe": windows_exe,
            "prefix": prefix, "before": before, "probe": probe, "built": built,
            "resolution": resolution}


def _dispatch(prepared: dict, mode: int) -> tuple[dict, bytes]:
    built, probe, resolution = (prepared[key] for key in ("built", "probe", "resolution"))
    folder = _folder(private_root() / "send-temporary")
    input_descriptor, input_name = tempfile.mkstemp(dir=folder)
    output_descriptor, output_name = tempfile.mkstemp(dir=folder)
    os.close(output_descriptor)
    try:
        with os.fdopen(input_descriptor, "wb") as stream:
            stream.write(prepared["chat"].encode("ascii").ljust(256, b"\0"))
            stream.write(prepared["text"].encode("utf-8").ljust(4096, b"\0"))
            stream.write(struct.pack("<III", prepared.get("input_kind", 2), prepared.get("width", 0), prepared.get("height", 0)))
            stream.write(prepared.get("filename", "").encode("utf-8").ljust(1024, b"\0"))
            stream.flush()
            os.fsync(stream.fileno())
        if client.processes(prepared["prefix"], prepared["executable"]) != prepared["before"]:
            raise ValueError("CLIENT_IDENTITY_CHANGED")
        nonce = secrets.randbelow(0xFFFFFFFF) + 1
        result = _invoke([prepared["wine"], str(built["message_dispatch"]), prepared["windows_exe"],
                          str(probe["windows_pid"]), str(probe["creation_filetime"]),
                          str(resolution["tid"]), resolution["hwnd"], _winpath(built["message_hook"]),
                          format(nonce, "x"), str(mode), _winpath(Path(input_name)),
                          resolution["manager"], _winpath(Path(output_name)),
                          prepared["value"]["self_id"]], prepared["env"])
        content = Path(output_name).read_bytes()
        if len(content) >= 4096:
            raise ValueError("INVALID_PREFLIGHT_CONTENT_SIZE")
        result["process_identity_unchanged"] = (
            client.processes(prepared["prefix"], prepared["executable"]) == prepared["before"])
        return result, content
    finally:
        Path(input_name).unlink(missing_ok=True)
        Path(output_name).unlink(missing_ok=True)


def _preflight(prepared: dict) -> dict:
    result, serialized = _dispatch(prepared, 1)
    # ModelMessage content is the RichMessage protobuf used by message.db.
    body_matches = decode(2, serialized).get("text") == prepared["text"]
    success = (result.get("ok") and result.get("process_identity_unchanged") and body_matches and
               not result.get("native_send_entered") and result.get("model_released") == 1 and
               result.get("info_released") == 1)
    return {"ok": bool(success), "status": "preflight_verified" if success else "preflight_failed",
            "body_matches": body_matches, "native": result, "message_send_performed": False,
            "artifact_digest": prepared["built"]["digest"], "helper_unload_policy": POLICY}


def preflight(name: str, chat: str, text: str) -> dict:
    with _lock():
        return _preflight(_prepare(name, chat, text))


def _reconcile(record: dict) -> dict:
    local_id = record.get("local_message_id")
    if not local_id:
        return record
    value = account(record["account"])
    if value["scope"] != record["account_scope"]:
        raise ValueError("REQUEST_ACCOUNT_CONFIGURATION_CHANGED")
    with open_snapshot(value["data_dir"] / "message.db", value["key_file"]) as (connection, _):
        rows = connection.execute("SELECT server_id,sender_id,conversation_id,content_type,content "
                                  "FROM message_table WHERE message_id=?", (local_id,)).fetchall()
    if len(rows) == 1:
        server, sender, chat, content_type, content = rows[0]
        if record.get("media_kind") == "image":
            from .sending_images import image_matches
            raw = bytes(content) if isinstance(content, (bytes, bytearray, memoryview)) else b""
            body_matches = image_matches(content_type, raw, record)
        else:
            body_matches = decode(content_type, content).get("text") == record["text"]
        matched = (str(sender) == value["self_id"] and chat == record["chat_id"] and
                   body_matches)
        record["local_history_integrated"] = matched
        if matched and str(server) not in ("0", "None", ""):
            record.update(status="sent_local_server_id_verified", ok=True,
                          server_message_id=str(server), message_send_performed=True)
    return record


def send_status(request_id: str) -> dict:
    path = _journal(request_id)
    with _lock():
        if not path.exists():
            raise ValueError("REQUEST_NOT_FOUND")
        record = _reconcile(read_private(path))
        _persist(path, record)
        return record


def send_text(name: str, chat: str, text: str, request_id: str) -> dict:
    path = _journal(request_id)
    if not isinstance(text, str) or not 1 <= len(text.encode("utf-8")) <= 3072 or "\0" in text:
        raise ValueError("TEXT_MUST_BE_1_TO_3072_UTF8_BYTES_WITHOUT_NUL")
    request_hash = hashlib.sha256(json.dumps([name, chat, text], ensure_ascii=False,
                                           separators=(",", ":")).encode()).hexdigest()
    with _lock():
        if path.exists():
            record = read_private(path)
            if record.get("request_hash") != request_hash:
                raise ValueError("REQUEST_ID_PAYLOAD_CONFLICT")
            record = _reconcile(record)
            _persist(path, record)
            return {**record, "replayed": True}
        for previous in path.parent.glob("*.json"):
            record = read_private(previous)
            if record.get("request_hash") == request_hash and record.get("status") == "submission_unknown":
                raise ValueError("SAME_OPERATION_UNKNOWN_QUERY_ORIGINAL_REQUEST")
        prepared = _prepare(name, chat, text)
        operation_hash = hashlib.sha256(json.dumps(
            [prepared["value"]["scope"], prepared["chat"], text],
            ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        for previous in path.parent.glob("*.json"):
            record = read_private(previous)
            if record.get("operation_hash") == operation_hash and record.get("status") == "submission_unknown":
                raise ValueError("SAME_OPERATION_UNKNOWN_QUERY_ORIGINAL_REQUEST")
        checked = _preflight(prepared)
        if not checked["ok"]:
            return checked
        record = {"ok": False, "status": "submission_unknown", "request_id": request_id,
                  "request_hash": request_hash, "account": name,
                  "operation_hash": operation_hash,
                  "account_scope": prepared["value"]["scope"], "chat_id": prepared["chat"],
                  "text": text, "preflight": checked, "process": prepared["before"][0],
                  "created_at": time.time(), "automatic_retry_allowed": False,
                  "native_submission_entered": None, "message_send_performed": None,
                  "local_history_integrated": False, "recipient_delivery_verified": False,
                  "helper_unload_policy": POLICY}
        # No native send is permitted before this atomic replace + directory fsync.
        _persist(path, record)
        try:
            result, _ = _dispatch(prepared, 2)
            record["native"] = result
            record["native_submission_entered"] = result.get("native_send_entered")
            if not result.get("native_send_entered") and result.get("state") == 2:
                record.update(status="rejected_before_submission", message_send_performed=False)
            if result.get("send_returned"):
                record["local_message_id"] = result["ids"][2]
            _persist(path, record)
            if record.get("local_message_id"):
                for _ in range(10):
                    record = _reconcile(record)
                    if record["ok"]:
                        break
                    time.sleep(0.5)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            record["error"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        record["completed_at"] = time.time()
        _persist(path, record)
        return record
