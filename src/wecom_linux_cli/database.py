"""Validate a stable copied database before allowing any schema inspection."""

import hashlib
import os
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from .crypto import SQLITE_HEADER, decrypt_bytes
from .state import private_root, read_private
from .wal import apply_wal


def _stamp(path: Path):
    try:
        s = path.stat()
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns
    except FileNotFoundError:
        return None


def stable_bytes(source: Path, attempts: int = 3) -> tuple[bytes, dict]:
    """Copy the DB and WAL twice under unchanged metadata, then merge commits.

    No source file is opened for writing or checkpointed. This is a stable
    pair, not a locked SQLite snapshot or a cross-database atomic snapshot.
    """
    wal = Path(str(source) + "-wal")
    journal = Path(str(source) + "-journal")
    for _ in range(attempts):
        before = _stamp(source), _stamp(wal), _stamp(journal)
        if before[0] is None:
            raise ValueError("DATABASE_NOT_FOUND")
        if before[2] and before[2][2]:
            raise ValueError("ROLLBACK_JOURNAL_NOT_YET_SUPPORTED")
        if any(stamp and stamp[2] > 1024 * 1024 * 1024 for stamp in before[:2]):
            raise ValueError("DATABASE_TOO_LARGE")
        try:
            data = source.read_bytes()
            wal_data = wal.read_bytes() if before[1] else b""
            second = source.read_bytes()
            wal_second = wal.read_bytes() if before[1] else b""
        except FileNotFoundError:
            continue
        after = _stamp(source), _stamp(wal), _stamp(journal)
        if before == after and data == second and wal_data == wal_second:
            evidence = {
                "source_sha256": hashlib.sha256(data).hexdigest(),
                "source_bytes": len(data),
                "snapshot_stable": True,
                "snapshot_atomic": False,
                "wal_present": bool(wal_data),
            }
            if wal_data:
                data, wal_evidence = apply_wal(data, wal_data)
                evidence.update(wal_evidence, wal_sha256=hashlib.sha256(wal_data).hexdigest(),
                                wal_bytes=len(wal_data), snapshot_bytes=len(data))
            return data, evidence
    raise ValueError("DATABASE_CHANGED_DURING_SNAPSHOT")


@contextmanager
def open_snapshot(source: Path, key_file: Path | None = None):
    data, evidence = stable_bytes(source)
    encrypted = not data.startswith(SQLITE_HEADER)
    if encrypted:
        if key_file is None:
            raise ValueError("DATABASE_KEY_REQUIRED")
        key_info = read_private(key_file)
        try:
            key = bytes.fromhex(key_info["raw_key_hex"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("INVALID_KEY_FILE") from exc
        data = decrypt_bytes(key, data)
    snapshots = private_root() / "snapshots"
    snapshots.mkdir(mode=0o700, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="read-", suffix=".db", dir=snapshots)
    conn = None
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        conn = sqlite3.connect(Path(name).as_uri() + "?mode=ro&immutable=1", uri=True)
        conn.execute("PRAGMA query_only=ON")
        deadline = time.monotonic() + 30
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        check = conn.execute("PRAGMA integrity_check").fetchall()
        if check != [("ok",)]:
            raise ValueError("DATABASE_INTEGRITY_CHECK_FAILED")
        evidence.update(encrypted=encrypted, integrity_verified=True)
        yield conn, evidence
    finally:
        if conn is not None:
            conn.close()
        Path(name).unlink(missing_ok=True)


def inspect(source: Path, key_file: Path | None = None) -> dict:
    with open_snapshot(source, key_file) as (conn, evidence):
        rows = conn.execute(
            "SELECT name, sql FROM sqlite_schema WHERE type='table' ORDER BY name"
        ).fetchall()
        return {"ok": True, "snapshot": evidence, "tables": [
            {"name": name, "schema": sql} for name, sql in rows
        ], "message_read_verified": False}
