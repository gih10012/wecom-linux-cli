import json
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

from test_content import length_field
import test_messages
from wecom_linux_cli import sending
from wecom_linux_cli.messages import account


class SendJournalTests(unittest.TestCase):
    setUp = test_messages.MessageReadTests.setUp
    tearDown = test_messages.MessageReadTests.tearDown

    def prepared(self, name, chat, text):
        return {"value": account(name), "chat": chat, "text": text,
                "before": [{"pid": 123, "start_time": 456}]}

    def dispatched(self, prepared, mode):
        # Simulate native entry only after the durable unknown record exists.
        record = json.loads(sending._journal("send-test-01").read_text())
        self.assertEqual(record["status"], "submission_unknown")
        self.assertFalse(record["automatic_retry_allowed"])
        raw = length_field(1, b"\x08\x00" + length_field(2, length_field(1, prepared["text"].encode())))
        with sqlite3.connect(self.data / "message.db") as connection:
            connection.execute("INSERT INTO message_table VALUES(46,987,123,?,2,101,?)",
                               (prepared["chat"], raw))
        return {"ok": True, "state": 2, "native_send_entered": True,
                "send_returned": True, "ids": [1, 0, 46, 0]}, b""

    def test_same_request_replay_and_changed_payload_never_dispatch_again(self):
        with patch.object(sending, "_prepare", side_effect=self.prepared), \
             patch.object(sending, "_preflight", return_value={"ok": True}), \
             patch.object(sending, "_dispatch", side_effect=self.dispatched) as dispatch:
            first = sending.send_text("me", "R:test", "中文\n✅", "send-test-01")
            second = sending.send_text("me", "R:test", "中文\n✅", "send-test-01")
            self.assertTrue(first["ok"])
            self.assertEqual(first["server_message_id"], "987")
            self.assertTrue(second["replayed"])
            with self.assertRaisesRegex(ValueError, "PAYLOAD_CONFLICT"):
                sending.send_text("me", "R:test", "changed", "send-test-01")
            self.assertEqual(dispatch.call_count, 1)

    def test_helper_timeout_persists_unknown_and_blocks_new_id_same_operation(self):
        with patch.object(sending, "_prepare", side_effect=self.prepared), \
             patch.object(sending, "_preflight", return_value={"ok": True}), \
             patch.object(sending, "_dispatch", side_effect=subprocess.TimeoutExpired("helper", 30)) as dispatch:
            first = sending.send_text("me", "R:test", "test", "send-test-01")
            self.assertEqual(first["status"], "submission_unknown")
            second = sending.send_text("me", "R:test", "test", "send-test-01")
            self.assertEqual(second["status"], "submission_unknown")
            with self.assertRaisesRegex(ValueError, "QUERY_ORIGINAL"):
                sending.send_text("me", "R:test", "test", "send-test-02")
            self.assertEqual(dispatch.call_count, 1)

    def test_crash_after_native_entry_keeps_durable_unknown_record(self):
        with patch.object(sending, "_prepare", side_effect=self.prepared), \
             patch.object(sending, "_preflight", return_value={"ok": True}), \
             patch.object(sending, "_dispatch", side_effect=KeyboardInterrupt) as dispatch:
            with self.assertRaises(KeyboardInterrupt):
                sending.send_text("me", "R:test", "test", "send-test-01")
            replay = sending.send_text("me", "R:test", "test", "send-test-01")
            self.assertEqual(replay["status"], "submission_unknown")
            self.assertEqual(dispatch.call_count, 1)

    def test_unknown_operation_cannot_bypass_guard_using_a_chat_name_alias(self):
        def alias(name, chat, text):
            return self.prepared(name, "R:test", text)
        with patch.object(sending, "_prepare", side_effect=alias), \
             patch.object(sending, "_preflight", return_value={"ok": True}), \
             patch.object(sending, "_dispatch", side_effect=subprocess.TimeoutExpired("helper", 30)) as dispatch:
            sending.send_text("me", "R:test", "test", "send-test-01")
            with self.assertRaisesRegex(ValueError, "QUERY_ORIGINAL"):
                sending.send_text("me", "a unique complete name", "test", "send-test-02")
            self.assertEqual(dispatch.call_count, 1)

    def test_readback_requires_correct_chat_body_sender_and_nonzero_server(self):
        value = account("me")
        record = {"account": "me", "account_scope": value["scope"], "chat_id": "R:test",
                  "text": "中文 45\n✅", "local_message_id": 45, "status": "submission_unknown",
                  "ok": False}
        for column, bad in (("sender_id", 456), ("conversation_id", "R:other"), ("server_id", 0)):
            with sqlite3.connect(self.data / "message.db") as connection:
                original = connection.execute("SELECT " + column + " FROM message_table WHERE message_id=45").fetchone()[0]
                connection.execute("UPDATE message_table SET " + column + "=? WHERE message_id=45", (bad,))
            self.assertFalse(sending._reconcile(dict(record))["ok"])
            with sqlite3.connect(self.data / "message.db") as connection:
                connection.execute("UPDATE message_table SET " + column + "=? WHERE message_id=45", (original,))
        self.assertTrue(sending._reconcile(dict(record))["ok"])
        self.assertFalse(sending._reconcile({**record, "text": "wrong"})["ok"])

    def test_preflight_failure_cannot_enter_real_dispatch(self):
        with patch.object(sending, "_prepare", side_effect=self.prepared), \
             patch.object(sending, "_preflight", return_value={"ok": False}), \
             patch.object(sending, "_dispatch") as dispatch:
            self.assertFalse(sending.send_text("me", "R:test", "test", "send-test-01")["ok"])
            dispatch.assert_not_called()

    def test_input_bounds_reject_before_any_native_code(self):
        with patch.object(sending, "_prepare") as prepare:
            for text in ("", "a\0b", "中" * 1025):
                with self.assertRaises(ValueError):
                    sending.send_text("me", "R:test", text, "send-test-01")
            with self.assertRaisesRegex(ValueError, "REQUEST_ID"):
                sending.send_text("me", "R:test", "test", "../escape")
            prepare.assert_not_called()
