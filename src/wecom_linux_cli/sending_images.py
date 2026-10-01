"""Native image dispatch using an immutable private copy and the shared journal."""

import hashlib
import json
import os
import stat
import struct
import subprocess
import time
import zlib
from pathlib import Path

from . import sending
from .content import fields
from .state import private_root, read_private


def dimensions(data: bytes) -> tuple[str, int, int]:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if (len(data) < 33 or data[8:16] != b"\0\0\0\rIHDR" or
                zlib.crc32(data[12:29]) != int.from_bytes(data[29:33], "big")):
            raise ValueError("INVALID_PNG_HEADER")
        width, height = struct.unpack_from(">II", data, 16)
        kind = "png"
    elif data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9"):
        offset, width, height = 2, 0, 0
        while offset < len(data):
            if data[offset] != 255:
                break
            while offset < len(data) and data[offset] == 255:
                offset += 1
            if offset >= len(data):
                break
            marker = data[offset]
            offset += 1
            if marker in (0, 0xD8, 0xD9, 0xDA) or offset + 2 > len(data):
                break
            length = int.from_bytes(data[offset:offset + 2], "big")
            if length < 2 or offset + length > len(data):
                break
            if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                          0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
                if length >= 8:
                    height, width = struct.unpack_from(">HH", data, offset + 3)
                break
            offset += length
        kind = "jpeg"
    else:
        raise ValueError("PNG_OR_JPEG_IMAGE_REQUIRED")
    if not (0 < width <= 32768 and 0 < height <= 32768 and width * height <= 64_000_000):
        raise ValueError("INVALID_OR_OVERSIZED_IMAGE_DIMENSIONS")
    return kind, width, height


def snapshot(source: Path) -> tuple[bytes, dict]:
    source = source.expanduser()
    filename = source.name
    if (not filename or len(filename.encode("utf-8")) > 768 or filename[-1] in ". " or
            any(ord(c) < 32 or c in '<>:"/\\|?*' for c in filename) or
            filename.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)], *[f"LPT{i}" for i in range(1, 10)]}):
        raise ValueError("INVALID_WINDOWS_IMAGE_FILENAME")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 10 * 1024 * 1024:
            raise ValueError("IMAGE_MUST_BE_REGULAR_FILE_1_BYTE_TO_10_MIB")
        data = stream.read(10 * 1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(data) != before.st_size:
        raise ValueError("IMAGE_CHANGED_DURING_SNAPSHOT")
    kind, width, height = dimensions(data)
    if source.suffix.lower() not in ((".png",) if kind == "png" else (".jpg", ".jpeg")):
        raise ValueError("IMAGE_EXTENSION_MUST_MATCH_FORMAT")
    return data, {"filename": filename, "format": kind, "width": width, "height": height,
                  "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                  "md5": hashlib.md5(data).hexdigest()}


def stage(data: bytes, image: dict) -> Path:
    digest = hashlib.sha256((image["filename"] + "\0" + image["sha256"]).encode()).hexdigest()
    folder = sending._folder(sending._folder(private_root() / "send-assets") / digest)
    path = folder / image["filename"]
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (info.st_uid != os.getuid() or info.st_mode & 0o077 or not stat.S_ISREG(info.st_mode) or
                    info.st_size != len(data) or stream.read(len(data) + 1) != data):
                raise ValueError("STAGED_IMAGE_CONFLICT")
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return path


def prepare(name: str, chat: str, data: bytes, image: dict) -> dict:
    staged = stage(data, image)
    result = sending._prepare(name, chat, sending._winpath(staged))
    result.update(input_kind=7, filename=image["filename"], width=image["width"],
                  height=image["height"], image=image, staged_image=staged)
    return result


def preflight_prepared(prepared: dict) -> dict:
    result, raw = sending._dispatch(prepared, 1)
    image = prepared["image"]
    expected = [(2, 2, image["filename"].encode()), (5, 0, image["width"]),
                (6, 0, image["height"]), (100, 2, prepared["text"].encode())]
    try:
        payload_matches = fields(raw) == expected
    except ValueError:
        payload_matches = False
    ok = bool(result.get("ok") and result.get("process_identity_unchanged") and payload_matches and
              not result.get("native_send_entered") and result.get("model_released") == 1 and result.get("info_released") == 1)
    return {"ok": ok, "status": "image_construct_verified" if ok else "image_construct_failed",
            "payload_matches": payload_matches, "native": result, "message_send_performed": False,
            "automatic_retry_allowed": False}


def preflight(name: str, chat: str, source: Path) -> dict:
    with sending._lock():
        data, image = snapshot(source)
        return preflight_prepared(prepare(name, chat, data, image))


def image_matches(kind: int, raw: bytes, record: dict) -> bool:
    if kind != 14:
        return False
    try:
        parsed = fields(raw)
    except ValueError:
        return False
    image = record["image"]
    expected = {2: image["filename"].encode(), 4: image["size"], 5: image["width"],
                6: image["height"], 10: image["md5"].encode()}
    for number, value in expected.items():
        wire = 2 if isinstance(value, bytes) else 0
        if [v for n, w, v in parsed if n == number and w == wire] != [value]:
            return False
    return True


def send_image(name: str, chat: str, source: Path, request_id: str) -> dict:
    path = sending._journal(request_id)
    with sending._lock():
        data, image = snapshot(source)
        request_hash = hashlib.sha256(json.dumps(["image", name, chat, image], ensure_ascii=False,
                                                separators=(",", ":")).encode()).hexdigest()
        if path.exists():
            record = read_private(path)
            if record["request_hash"] != request_hash:
                raise ValueError("REQUEST_ID_PAYLOAD_CONFLICT")
            record = sending._reconcile(record)
            sending._persist(path, record)
            return {**record, "replayed": True}
        for previous in path.parent.glob("*.json"):
            old = read_private(previous)
            if old.get("request_hash") == request_hash and old.get("status") == "submission_unknown":
                raise ValueError("SAME_OPERATION_UNKNOWN_QUERY_ORIGINAL_REQUEST")
        prepared = prepare(name, chat, data, image)
        operation_hash = hashlib.sha256(json.dumps(
            ["image", prepared["value"]["scope"], prepared["chat"], image],
            ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        for previous in path.parent.glob("*.json"):
            old = read_private(previous)
            if old.get("operation_hash") == operation_hash and old.get("status") == "submission_unknown":
                raise ValueError("SAME_OPERATION_UNKNOWN_QUERY_ORIGINAL_REQUEST")
        checked = preflight_prepared(prepared)
        if not checked["ok"]:
            return checked
        record = {"ok": False, "status": "submission_unknown", "request_id": request_id,
                  "request_hash": request_hash, "operation_hash": operation_hash, "account": name,
                  "account_scope": prepared["value"]["scope"], "chat_id": prepared["chat"],
                  "media_kind": "image", "image": image, "staged_image": str(prepared["staged_image"]),
                  "preflight": checked, "process": prepared["before"][0], "created_at": time.time(),
                  "automatic_retry_allowed": False, "native_submission_entered": None,
                  "message_send_performed": None, "local_history_integrated": False,
                  "recipient_delivery_verified": False, "helper_unload_policy": sending.POLICY}
        sending._persist(path, record)
        try:
            # Preserve the copied path through async uploads and unknown outcomes.
            if hashlib.sha256(prepared["staged_image"].read_bytes()).hexdigest() != image["sha256"]:
                raise ValueError("STAGED_IMAGE_CHANGED")
            result, _ = sending._dispatch(prepared, 2)
            record["native"] = result
            record["native_submission_entered"] = result.get("native_send_entered")
            if not result.get("native_send_entered") and result.get("state") == 2:
                record.update(status="rejected_before_submission", message_send_performed=False)
            if result.get("send_returned"):
                record["local_message_id"] = result["ids"][2]
            sending._persist(path, record)
            if record.get("local_message_id"):
                for _ in range(30):
                    record = sending._reconcile(record)
                    if record["ok"]:
                        break
                    time.sleep(0.5)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            record["error"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        record["completed_at"] = time.time()
        sending._persist(path, record)
        return record
