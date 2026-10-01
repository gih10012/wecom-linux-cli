import hashlib
import os
import sqlite3
import struct
import tempfile
import unittest
import zlib
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from wecom_linux_cli.media import export
from wecom_linux_cli.messages import configure
from wecom_linux_cli.state import private_root, write_private


def varint(n):
    result = bytearray()
    while n > 127:
        result.append((n & 127) | 128)
        n >>= 7
    return bytes(result + bytes([n]))


def length_field(number, data):
    return varint(number * 8 + 2) + varint(len(data)) + data


def png():
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(b"\0\xff\0\0")) + chunk(b"IEND", b""))


class CachedOriginalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.env = patch.dict(os.environ, {"XDG_STATE_HOME": str(self.root / "state")})
        self.env.start()
        prefix = self.root / "prefix"
        self.account = prefix / "drive_c/Users/test/Documents/WXWork/123"
        self.data = self.account / "Data"
        self.data.mkdir(parents=True)
        self.original = png()
        md5 = hashlib.md5(self.original).hexdigest()
        raw = length_field(3, b"original-key") + b"\x20" + varint(len(self.original)) + length_field(10, md5.encode()) + length_field(26, b"thumbnail-key")
        with closing(sqlite3.connect(self.data / "message.db")) as c, c:
            c.execute("CREATE TABLE message_table(message_id INTEGER PRIMARY KEY,server_id INTEGER,sender_id INTEGER,conversation_id TEXT,content_type INTEGER,send_time INTEGER,content BLOB)")
            c.execute("INSERT INTO message_table VALUES(1,5,777,'S:123_777',101,100,?)", (raw,))
        with closing(sqlite3.connect(self.data / "session.db")) as c, c:
            c.execute("CREATE TABLE conversation_table(id TEXT,name TEXT,last_message_time INTEGER)")
            c.execute("INSERT INTO conversation_table VALUES('S:123_777','peer',100)")
        with closing(sqlite3.connect(self.data / "user.db")) as c, c:
            c.execute("CREATE TABLE user_table(id INTEGER,name TEXT)")
        self.mapping = self.account / "CacheMapping/test.db"
        self.mapping.parent.mkdir()
        with closing(sqlite3.connect(self.mapping)) as c, c:
            c.execute("CREATE TABLE mapping(type INTEGER,key TEXT,file_name TEXT,last_modify_time INTEGER,file_md5 TEXT)")
            c.executemany("INSERT INTO mapping VALUES(2,?,?,0,'')", [
                ("original-key", "2026-10\\original.png"), ("thumbnail-key", "2026-10\\thumb.jpg")])
        self.image = self.account / "Cache/Image/2026-10/original.png"
        self.image.parent.mkdir(parents=True)
        self.image.write_bytes(self.original)
        (self.image.parent / "thumb.jpg").write_bytes(b"thumbnail")
        key = self.root / "key.json"
        write_private(key, {})
        write_private(private_root() / "client.json", {"prefix": str(prefix)})
        configure("me", self.data, key)

    def tearDown(self):
        self.env.stop()
        self.temporary.cleanup()

    def test_export_and_replay_preserve_original_bytes_and_private_mode(self):
        result = export("me", "S:123_777", 1)
        output = Path(result["path"])
        self.assertEqual(output.read_bytes(), self.original)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertFalse(result["remote_download_performed"])
        self.assertFalse(result["thumbnail_used"])
        self.assertEqual(export("me", "peer", 1)["path"], result["path"])

    def test_thumbnail_is_not_used_when_original_is_missing(self):
        self.image.unlink()
        with self.assertRaisesRegex(ValueError, "ORIGINAL_IMAGE_NOT_CACHED"):
            export("me", "S:123_777", 1)

    def test_native_image_uses_original_key_and_absolute_account_cache(self):
        md5 = hashlib.md5(self.original).hexdigest()
        raw = (length_field(1, b"original-key") + length_field(2, b"photo.png") +
               b"\x20" + varint(len(self.original)) + length_field(10, md5.encode()) +
               length_field(26, b"thumbnail-key"))
        with closing(sqlite3.connect(self.data / "message.db")) as c, c:
            c.execute("UPDATE message_table SET content_type=14,content=?", (raw,))
        with closing(sqlite3.connect(self.mapping)) as c, c:
            c.execute("UPDATE mapping SET file_name=? WHERE key='original-key'",
                      (r"C:\Users\test\Documents\WXWork\123\Cache\Image\2026-10\original.png",))
        result = export("me", "S:123_777", 1)
        self.assertEqual(Path(result["path"]).read_bytes(), self.original)
        self.assertFalse(result["thumbnail_used"])

    def test_absolute_windows_mapping_cannot_escape_configured_account(self):
        for path in (r"D:\Users\test\Documents\WXWork\123\Cache\Image\original.png",
                     r"C:\Users\test\Documents\WXWork\999\Cache\Image\original.png",
                     r"C:\Users\test\Documents\WXWork\123\Cache\Image\..\original.png",
                     r"\\server\share\original.png", r"C:original.png",
                     r"C:\Users\test\Documents\WXWork\123\Cache\Image\original.png:stream"):
            with self.subTest(path=path):
                with closing(sqlite3.connect(self.mapping)) as c, c:
                    c.execute("UPDATE mapping SET file_name=? WHERE key='original-key'", (path,))
                with self.assertRaisesRegex(ValueError, "OUTSIDE_ACCOUNT"):
                    export("me", "S:123_777", 1)

    def test_same_size_corruption_fails_hash_check(self):
        data = bytearray(self.original)
        data[-1] ^= 1
        self.image.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "HASH_MISMATCH"):
            export("me", "S:123_777", 1)

    def test_message_cannot_be_exported_from_another_chat(self):
        with self.assertRaisesRegex(ValueError, "EXACT_CHAT"):
            export("me", "S:123_888", 1)

    def test_cache_path_traversal_and_symlink_are_rejected(self):
        with closing(sqlite3.connect(self.mapping)) as c, c:
            c.execute("UPDATE mapping SET file_name='../outside.png' WHERE key='original-key'")
        with self.assertRaisesRegex(ValueError, "OUTSIDE_ACCOUNT"):
            export("me", "S:123_777", 1)
        with closing(sqlite3.connect(self.mapping)) as c, c:
            c.execute("UPDATE mapping SET file_name='2026-10/original.png' WHERE key='original-key'")
        other = self.root / "outside.png"
        other.write_bytes(self.original)
        self.image.unlink()
        self.image.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "OUTSIDE_ACCOUNT"):
            export("me", "S:123_777", 1)
