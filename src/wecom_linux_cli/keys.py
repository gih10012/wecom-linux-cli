"""Capture candidate cipher keys through a bounded read-only Wine helper.

Candidates are not credentials accepted on trust: the actual database's
encrypted first block and full SQLite integrity must both validate a key.
"""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .client import config, environment, processes
from .crypto import SQLITE_HEADER, page_size, verify_key
from .database import open_snapshot, stable_bytes
from .state import private_root, write_private


def helper() -> Path:
    source = Path(__file__).parent / "_native/client_probe.c"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    folder = private_root() / "native" / digest
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    executable = folder / "client_probe.exe"
    if executable.is_file():
        if executable.stat().st_uid != os.getuid() or executable.stat().st_mode & 0o077:
            raise ValueError("UNSAFE_HELPER_PERMISSIONS")
        return executable
    compiler = shutil.which("i686-w64-mingw32-gcc")
    if not compiler:
        raise ValueError("MINGW32_COMPILER_REQUIRED")
    fd, temporary = tempfile.mkstemp(prefix="build-", suffix=".exe", dir=folder)
    os.close(fd)
    try:
        result = subprocess.run([compiler, "-O2", "-Wall", "-Wextra", "-Werror",
                                 "-municode", str(source), "-o", temporary],
                                capture_output=True, timeout=60)
        if result.returncode:
            raise ValueError("NATIVE_HELPER_BUILD_FAILED")
        Path(temporary).chmod(0o700)
        os.replace(temporary, executable)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return executable


def _result(args: list[str], env: dict) -> dict:
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=40)
    lines = [line for line in result.stdout.splitlines() if line.startswith("{")]
    if len(lines) != 1:
        raise ValueError("AMBIGUOUS_OR_MISSING_CLIENT_PROBE")
    value = json.loads(lines[0])
    if result.returncode or not value.get("ok"):
        raise ValueError(value.get("code", "CLIENT_PROBE_FAILED"))
    return value


def capture(source: Path) -> dict:
    current = config()
    if not current.get("prefix") or not current.get("executable"):
        raise ValueError("CLIENT_NOT_CONFIGURED")
    prefix = Path(current["prefix"]).resolve()
    if prefix.stat().st_uid != os.getuid() or prefix.stat().st_mode & 0o077:
        raise ValueError("UNSAFE_WINE_PREFIX")
    drive = prefix / "drive_c"
    executable = Path(current["executable"]).resolve()
    source = source.resolve()
    if not executable.is_relative_to(drive) or not source.is_relative_to(drive):
        raise ValueError("PATH_OUTSIDE_CONFIGURED_WINE_PREFIX")
    before = processes(prefix, executable)
    if len(before) != 1:
        raise ValueError("ONE_RUNNING_CLIENT_REQUIRED")
    data, _ = stable_bytes(source)
    if data.startswith(SQLITE_HEADER):
        raise ValueError("PLAINTEXT_DATABASE_NEEDS_NO_KEY")
    size = page_size(data)
    first = data[:size]
    wine = shutil.which("wine")
    if not wine:
        raise ValueError("WINE_NOT_INSTALLED")
    if (prefix / "dosdevices/z:").resolve() != Path("/"):
        raise ValueError("STANDARD_WINE_Z_MAPPING_REQUIRED")
    env = environment(current)
    env["WINEDEBUG"] = "-all"
    args = [wine, str(helper()), "C:\\" + str(executable.relative_to(drive)).replace("/", "\\")]
    probe = _result(args, env)
    root = private_root()
    fd, candidate_name = tempfile.mkstemp(prefix="candidates-", dir=root)
    os.close(fd)
    temporary_key = None
    try:
        scan = _result(args + [str(probe["windows_pid"]), str(probe["creation_filetime"]),
                               "Z:" + candidate_name.replace("/", "\\")], env)
        if processes(prefix, executable) != before or not scan.get("identity_unchanged"):
            raise ValueError("CLIENT_IDENTITY_CHANGED")
        path = Path(candidate_name)
        info = path.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 1048576:
            raise ValueError("UNSAFE_CANDIDATE_FILE")
        candidates = path.read_bytes()
        if len(candidates) != scan["candidate_count"] * 16:
            raise ValueError("INCOMPLETE_CANDIDATE_FILE")
        matches = {candidates[i:i+16] for i in range(0, len(candidates), 16)
                   if verify_key(candidates[i:i+16], first)}
        if len(matches) != 1:
            raise ValueError("UNIQUE_VERIFIED_DATABASE_KEY_NOT_FOUND")
        key = matches.pop()
        fd, name = tempfile.mkstemp(prefix="key-check-", suffix=".json", dir=root)
        os.close(fd)
        temporary_key = Path(name)
        write_private(temporary_key, {"raw_key_hex": key.hex()})
        with open_snapshot(source, temporary_key) as (_, evidence):
            pass
        if processes(prefix, executable) != before:
            raise ValueError("CLIENT_IDENTITY_CHANGED")
        keys = root / "keys"
        keys.mkdir(mode=0o700, exist_ok=True)
        target = keys / (hashlib.sha256(os.fsencode(str(source))).hexdigest() + ".json")
        write_private(target, {"raw_key_hex": key.hex(), "database": str(source),
                               "process": before[0], "snapshot": evidence})
        return {"ok": True, "key_file": str(target), "snapshot": evidence,
                "scan_complete": scan["scan_complete"], "scanned_bytes": scan["scanned_bytes"],
                "candidate_count": scan["candidate_count"], "process_identity_unchanged": True,
                "message_read_verified": False, "native_call_performed": False}
    finally:
        Path(candidate_name).unlink(missing_ok=True)
        if temporary_key is not None:
            temporary_key.unlink(missing_ok=True)
