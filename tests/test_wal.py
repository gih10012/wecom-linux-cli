import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wecom_linux_cli.database import open_snapshot
from wecom_linux_cli.wal import apply_wal


class WalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "source.db"
        self.conn = sqlite3.connect(self.path)
        self.conn.execute("PRAGMA page_size=4096")
        self.conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, body TEXT)")
        self.conn.commit()
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA wal_autocheckpoint=0")
        self.conn.execute("INSERT INTO sample VALUES(1,?)", ("中文\n完整 ✅",))
        self.conn.commit()
        self.conn.execute("INSERT INTO sample VALUES(2,?)", ("x" * 12000,))
        self.conn.commit()
        self.base = self.path.read_bytes()
        self.wal = Path(str(self.path) + "-wal").read_bytes()

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def test_independent_sqlite_wal_commit_and_extension(self):
        data, evidence = apply_wal(self.base, self.wal)
        path = self.root / "merged.db"
        path.write_bytes(data)
        conn = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(conn.execute("SELECT body FROM sample WHERE id=1").fetchone()[0], "中文\n完整 ✅")
            self.assertEqual(conn.execute("SELECT length(body) FROM sample WHERE id=2").fetchone()[0], 12000)
            self.assertGreater(len(data), len(self.base))
            self.assertTrue(evidence["wal_checksum_verified"])
        finally:
            conn.close()

    def test_uncommitted_spilled_transaction_is_excluded(self):
        self.conn.execute("PRAGMA cache_size=2")
        self.conn.execute("BEGIN")
        self.conn.executemany("INSERT INTO sample(body) VALUES(?)", [("pending" * 1000,)] * 20)
        wal = Path(str(self.path) + "-wal").read_bytes()
        data, evidence = apply_wal(self.base, wal)
        self.assertGreater(evidence["wal_uncommitted_frames"], 0)
        path = self.root / "merged.db"
        path.write_bytes(data)
        conn = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM sample").fetchone()[0], 2)
        finally:
            conn.close()

    def test_stale_salt_ends_current_wal_cycle(self):
        frame = bytearray(self.wal[-4120:])
        frame[8] ^= 1
        data, evidence = apply_wal(self.base, self.wal + frame)
        expected, _ = apply_wal(self.base, self.wal)
        self.assertEqual(data, expected)
        self.assertEqual(evidence["wal_stale_trailing_frames"], 1)

    def test_corrupt_ciphertext_or_header_fails_instead_of_ignoring_wal(self):
        for offset in (20, 70):
            damaged = bytearray(self.wal)
            damaged[offset] ^= 1
            with self.assertRaisesRegex(ValueError, "CHECKSUM_MISMATCH"):
                apply_wal(self.base, damaged)

    def test_partial_frame_rejected(self):
        with self.assertRaisesRegex(ValueError, "INCOMPLETE_WAL_FRAME"):
            apply_wal(self.base, self.wal[:-1])

    def test_live_snapshot_preserves_db_wal_and_removes_plaintext(self):
        before = self.path.read_bytes(), Path(str(self.path) + "-wal").read_bytes()
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(self.root / "state")}):
            with open_snapshot(self.path) as (conn, evidence):
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM sample").fetchone()[0], 2)
                self.assertTrue(evidence["wal_checksum_verified"])
                with self.assertRaises(sqlite3.OperationalError):
                    conn.execute("DELETE FROM sample")
            self.assertEqual(list((self.root / "state/wecom-linux-cli/snapshots").iterdir()), [])
        self.assertEqual(before, (self.path.read_bytes(), Path(str(self.path) + "-wal").read_bytes()))
