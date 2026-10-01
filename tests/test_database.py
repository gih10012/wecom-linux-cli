import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wecom_linux_cli.crypto import decrypt_bytes, verify_key
from wecom_linux_cli.database import inspect, open_snapshot, stable_bytes
from wecom_linux_cli.state import read_private, write_private

FIXTURE = Path(__file__).parent / "fixtures/sqlite3mc-aes128.enc"
TEST_KEY = bytes(range(16))


class DecoderTests(unittest.TestCase):
    def test_independent_upstream_cipher_fixture(self):
        data = decrypt_bytes(TEST_KEY, FIXTURE.read_bytes())
        db = sqlite3.connect(":memory:")
        try:
            db.deserialize(data)
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(db.execute("SELECT body FROM sample WHERE id=1").fetchone()[0], "中文、换行测试 ✅")
            self.assertEqual(db.execute("SELECT length(body) FROM sample WHERE id=2").fetchone()[0], 9000)
        finally:
            db.close()

    def test_wrong_key_is_not_accepted_by_reconstructed_magic(self):
        encrypted = FIXTURE.read_bytes()
        self.assertFalse(verify_key(b"x" * 16, encrypted[:4096]))
        with self.assertRaisesRegex(ValueError, "KEY_MISMATCH"):
            decrypt_bytes(b"x" * 16, encrypted)

    def test_partial_database_rejected(self):
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_DATABASE_FILE"):
            decrypt_bytes(TEST_KEY, FIXTURE.read_bytes()[:-1])


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {"XDG_STATE_HOME": str(self.root / "state")})
        self.env.start()
        self.source = self.root / "source.db"
        self.source.write_bytes(FIXTURE.read_bytes())
        self.key = self.root / "key.json"
        write_private(self.key, {"raw_key_hex": TEST_KEY.hex()})

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_schema_inspection_preserves_source_and_cleans_plaintext(self):
        original = self.source.read_bytes()
        result = inspect(self.source, self.key)
        self.assertEqual([x["name"] for x in result["tables"]], ["sample"])
        self.assertTrue(result["snapshot"]["integrity_verified"])
        self.assertFalse(result["snapshot"]["snapshot_atomic"])
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(list((self.root / "state/wecom-linux-cli/snapshots").iterdir()), [])

    def test_snapshot_disallows_writes(self):
        with open_snapshot(self.source, self.key) as (db, _):
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("UPDATE sample SET body='mutated'")

    def test_live_wal_requires_implemented_validated_reader(self):
        Path(str(self.source) + "-wal").write_bytes(b"not-yet-supported")
        with self.assertRaisesRegex(ValueError, "LIVE_WAL_NOT_YET_SUPPORTED"):
            stable_bytes(self.source)

    def test_bad_key_file_permissions_rejected(self):
        self.key.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "UNSAFE_PRIVATE_FILE_PERMISSIONS"):
            read_private(self.key)

    def test_encrypted_data_requires_private_key(self):
        with self.assertRaisesRegex(ValueError, "DATABASE_KEY_REQUIRED"):
            inspect(self.source)

    def test_corrupt_page_rejected_by_integrity_check(self):
        data = bytearray(self.source.read_bytes())
        data[4096:4112] = bytes(16)
        self.source.write_bytes(data)
        with self.assertRaises((ValueError, sqlite3.DatabaseError)):
            inspect(self.source, self.key)


if __name__ == "__main__":
    unittest.main()

