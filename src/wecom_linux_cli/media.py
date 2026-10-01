"""Export verified full images already cached by the owner's client.

This performs no remote request. A missing original must be loaded normally
in the client; a thumbnail cannot stand in for the original message payload.
"""

import hashlib
import os
import re
import tempfile
from pathlib import Path

from .content import fields
from .database import open_snapshot
from .messages import account, names
from .state import private_root

MAX_IMAGE_BYTES = 10 * 1024 * 1024


def _single(parsed, number, wire):
    values = [value for n, w, value in parsed if n == number and w == wire]
    if len(values) != 1:
        raise ValueError("AMBIGUOUS_OR_MISSING_IMAGE_REFERENCE")
    return values[0]


def _read_original(path: Path, expected_size: int, md5: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_uid != os.getuid() or before.st_size != expected_size:
            raise ValueError("CACHE_ORIGINAL_SIZE_OR_OWNER_MISMATCH")
        data = stream.read(expected_size + 1)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("CACHE_CHANGED_DURING_READ")
    if len(data) != expected_size or hashlib.md5(data).hexdigest() != md5:
        raise ValueError("CACHE_ORIGINAL_HASH_MISMATCH")
    return data


def export(name: str, chat: str, message_id: int) -> dict:
    if message_id < 1:
        raise ValueError("INVALID_MESSAGE_ID")
    value = account(name)
    _, chats, snapshots = names(value)
    if chat not in chats:
        matches = [cid for cid, title in chats.items() if title == chat]
        if len(matches) > 1:
            raise ValueError("AMBIGUOUS_CHAT_NAME_USE_EXACT_ID")
        if matches:
            chat = matches[0]
    with open_snapshot(value["data_dir"] / "message.db", value["key_file"]) as (conn, snapshot):
        snapshots["message.db"] = snapshot
        row = conn.execute("SELECT content_type,content,server_id FROM message_table "
                           "WHERE message_id=? AND conversation_id=?", (message_id, chat)).fetchone()
    if row is None:
        raise ValueError("MESSAGE_NOT_FOUND_IN_EXACT_CHAT")
    if row[0] != 101:
        raise ValueError("MEDIA_TYPE_NOT_SUPPORTED_FOR_EXPORT")
    parsed = fields(bytes(row[1]))
    key = _single(parsed, 3, 2)  # External WeChat image's original cache key.
    expected_size = _single(parsed, 4, 0)
    md5 = _single(parsed, 10, 2).decode("ascii")
    if not 1 <= expected_size <= MAX_IMAGE_BYTES or not re.fullmatch(r"[0-9a-f]{32}", md5):
        raise ValueError("INVALID_OR_UNSUPPORTED_IMAGE_REFERENCE")
    root = value["data_dir"].parent.resolve()
    mapping = root / "CacheMapping"
    cache = root / "Cache" / "Image"
    if (mapping.is_symlink() or cache.is_symlink() or
            not mapping.resolve().is_relative_to(root) or not cache.resolve().is_relative_to(root)):
        raise ValueError("CACHE_PATH_OUTSIDE_ACCOUNT")
    databases = sorted(mapping.glob("*.db"))
    if len(databases) > 16:
        raise ValueError("TOO_MANY_CACHE_MAPPING_DATABASES")
    try:
        text_key = key.decode("utf-8")
    except UnicodeError:
        text_key = None
    candidates = set()
    for database in databases:
        if database.is_symlink():
            raise ValueError("CACHE_MAPPING_SYMLINK")
        with open_snapshot(database, None) as (conn, snapshot):
            columns = {r[1] for r in conn.execute('PRAGMA table_info("mapping")')}
            if not {"type", "key", "file_name"} <= columns:
                raise ValueError("UNSUPPORTED_CACHE_MAPPING_SCHEMA")
            snapshots["CacheMapping/" + database.name] = snapshot
            for (filename,) in conn.execute("SELECT file_name FROM mapping WHERE type=2 AND (key=? OR key=?)",
                                            (key, text_key)):
                if not isinstance(filename, str) or not filename or len(filename) > 1024:
                    raise ValueError("UNSUPPORTED_CACHE_FILENAME")
                relative = Path(filename.replace("\\", "/"))
                if relative.is_absolute() or ".." in relative.parts or ":" in filename:
                    raise ValueError("CACHE_PATH_OUTSIDE_ACCOUNT")
                path = cache / relative
                if path.is_symlink() or not path.resolve().is_relative_to(cache.resolve()):
                    raise ValueError("CACHE_PATH_OUTSIDE_ACCOUNT")
                if path.is_file():
                    candidates.add(path)
    if not candidates:
        raise ValueError("ORIGINAL_IMAGE_NOT_CACHED_OPEN_IN_CLIENT")
    if len(candidates) != 1:
        raise ValueError("AMBIGUOUS_ORIGINAL_IMAGE_CACHE")
    data = _read_original(candidates.pop(), expected_size, md5)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        extension, mime = "png", "image/png"
    elif data.startswith(b"\xff\xd8\xff"):
        extension, mime = "jpg", "image/jpeg"
    else:
        raise ValueError("UNSUPPORTED_CACHED_IMAGE_FORMAT")
    folder = private_root() / "attachments"
    folder.mkdir(mode=0o700, exist_ok=True)
    info = folder.lstat()
    if folder.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("UNSAFE_MEDIA_EXPORT_DIRECTORY")
    output = folder / f"{value['scope'][:16]}-{message_id}-{md5}.{extension}"
    fd, temporary = tempfile.mkstemp(dir=folder)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, output)  # Never overwrite a conflicting export.
        except FileExistsError:
            if output.is_symlink() or output.stat().st_mode & 0o077:
                raise ValueError("UNSAFE_EXISTING_MEDIA_EXPORT")
            if _read_original(output, expected_size, md5) != data:
                raise ValueError("MEDIA_EXPORT_CONFLICT")
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {"ok": True, "account": name, "chat_id": chat, "message_id": message_id,
            "server_id": str(row[2]), "path": str(output), "bytes": len(data), "md5": md5,
            "sha256": hashlib.sha256(data).hexdigest(), "mime_type": mime,
            "original_hash_verified": True, "source": "verified_client_original_cache",
            "remote_download_performed": False, "thumbnail_used": False,
            "snapshots": snapshots, "message_send_performed": False}
