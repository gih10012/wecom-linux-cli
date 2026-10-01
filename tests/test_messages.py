import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wecom_linux_cli.messages import configure, conversations, messages
from wecom_linux_cli.state import private_root, write_private
from test_content import length_field


class MessageReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {"XDG_STATE_HOME": str(self.root / "state")})
        self.env.start()
        self.data = self.root / "prefix/drive_c/Users/test/Documents/WXWork/123/Data"
        self.data.mkdir(parents=True)
        write_private(private_root() / "client.json", {"prefix": str(self.root / "prefix")})
        self.key = self.root / "key.json"
        write_private(self.key, {})
        with sqlite3.connect(self.data / "message.db") as conn:
            conn.execute("CREATE TABLE message_table(message_id INTEGER PRIMARY KEY,server_id INTEGER,sender_id INTEGER,conversation_id TEXT,content_type INTEGER,send_time INTEGER,content BLOB)")
            for number in range(1, 46):
                text = f"中文 {number}\n✅"
                raw = length_field(1, b"\x08\x00" + length_field(2, length_field(1, text.encode())))
                conn.execute("INSERT INTO message_table VALUES(?,?,?,'R:test',0,100,?)", (number, number, 123, raw))
        with sqlite3.connect(self.data / "session.db") as conn:
            conn.execute("CREATE TABLE conversation_table(id TEXT,name TEXT,last_message_time INTEGER)")
            conn.executemany("INSERT INTO conversation_table VALUES(?,?,100)", [("R:test", "测试群"), ("R:duplicate", "测试群"), ("S:123_123", "")])
        with sqlite3.connect(self.data / "user.db") as conn:
            conn.execute("CREATE TABLE user_table(id INTEGER,name TEXT)")
            conn.execute("INSERT INTO user_table VALUES(123,'测试用户')")
        configure("me", self.data, self.key)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_equal_timestamps_page_without_gaps_and_exclude_new_insertions(self):
        first = messages("me", "R:test")
        self.assertEqual(len(first["items"]), 20)
        with sqlite3.connect(self.data / "message.db") as conn:
            conn.execute("INSERT INTO message_table VALUES(46,46,123,'R:test',0,100,X'')")
        second = messages("me", "R:test", cursor=first["next_cursor"])
        third = messages("me", "R:test", cursor=second["next_cursor"])
        combined = [r["message_id"] for page in (first, second, third) for r in page["items"]]
        self.assertEqual(combined, list(range(45, 0, -1)))
        self.assertIsNone(third["next_cursor"])
        self.assertEqual(first["items"][0]["content"]["text"], "中文 45\n✅")

    def test_all_returns_complete_local_history(self):
        result = messages("me", "R:test", all_history=True)
        self.assertEqual(len(result["items"]), 45)
        self.assertIsNone(result["next_cursor"])
        self.assertFalse(result["remote_history_complete"])

    def test_large_server_and_sender_ids_keep_exact_integer_precision(self):
        with sqlite3.connect(self.data / "message.db") as conn:
            conn.execute("UPDATE message_table SET server_id=9223372036854775806,sender_id=9223372036854775805 WHERE message_id=45")
        row = messages("me", "R:test")["items"][0]
        self.assertEqual(row["server_id"], "9223372036854775806")
        self.assertEqual(row["sender_id"], "9223372036854775805")
        self.assertEqual(row["stored_fields"]["server_id"], "9223372036854775806")

    def test_ambiguous_name_and_cross_chat_cursor_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "AMBIGUOUS_CHAT_NAME"):
            messages("me", "测试群")
        first = messages("me", "R:test")
        with self.assertRaisesRegex(ValueError, "WRONG_SCOPE_CURSOR"):
            messages("me", "R:duplicate", cursor=first["next_cursor"])

    def test_filehelper_name_and_conversation_cursor(self):
        result = conversations(query="文件传输助手")
        self.assertEqual(result["items"][0]["chat_id"], "FILEASSIST")
        self.assertEqual(messages("me", "S:123_123")["chat_name"], "测试用户")
        first = conversations(limit=1)
        second = conversations(limit=1, cursor=first["next_cursor"])
        self.assertNotEqual(first["items"][0]["chat_id"], second["items"][0]["chat_id"])

    def test_arbitrary_exact_id_is_not_a_recipient_whitelist(self):
        self.assertEqual(messages("me", "arbitrary:exact-id")["items"], [])
