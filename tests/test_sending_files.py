import hashlib
import json
import sqlite3
import subprocess
import unittest
from unittest.mock import patch

import test_messages
from test_media import png, varint, length_field
from wecom_linux_cli import sending, sending_files as files, sending_images as images
from wecom_linux_cli.messages import account


class FileSendTests(unittest.TestCase):
    setUp = test_messages.MessageReadTests.setUp
    tearDown = test_messages.MessageReadTests.tearDown

    def source(self):
        source = self.data / "中文文件.txt"
        source.write_bytes("中文\nfile ✅\n".encode())
        return source

    def prepared(self, name, chat, data, metadata):
        return {"value": account(name), "chat": "R:test", "before": [{"pid": 123}],
                "text": "Z:\\staged\\" + metadata["filename"], "file": metadata,
                "staged_file": images.stage(data, metadata)}

    def stored(self, metadata):
        return b"".join((length_field(2, metadata["filename"].encode()),
                         b"\x20" + varint(metadata["size"]), length_field(10, metadata["md5"].encode())))

    def dispatched(self, prepared, mode):
        record = json.loads(sending._journal("file-test-01").read_text())
        self.assertEqual(record["status"], "submission_unknown")
        self.assertFalse(record["automatic_retry_allowed"])
        with sqlite3.connect(self.data / "message.db") as conn:
            conn.execute("INSERT INTO message_table VALUES(46,987,123,?,15,101,?)",
                         (prepared["chat"], self.stored(prepared["file"])))
        return {"ok": True, "state": 2, "native_send_entered": True,
                "send_returned": True, "ids": [1, 0, 46, 0]}, b""

    def test_replay_filename_bytes_and_media_kind_conflicts(self):
        source = self.source()
        with patch.object(files, "prepare", side_effect=self.prepared), \
             patch.object(files, "preflight_prepared", return_value={"ok": True}), \
             patch.object(sending, "_dispatch", side_effect=self.dispatched) as dispatch:
            self.assertTrue(files.send_file("me", "R:test", source, "file-test-01")["ok"])
            self.assertTrue(files.send_file("me", "R:test", source, "file-test-01")["replayed"])
            renamed = source.with_name("改名.zip")
            renamed.write_bytes(source.read_bytes())
            with self.assertRaisesRegex(ValueError, "PAYLOAD_CONFLICT"):
                files.send_file("me", "R:test", renamed, "file-test-01")
            source.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "PAYLOAD_CONFLICT"):
                files.send_file("me", "R:test", source, "file-test-01")
            image = source.with_name("图片.png")
            image.write_bytes(png())
            with self.assertRaisesRegex(ValueError, "PAYLOAD_CONFLICT"):
                images.send_image("me", "R:test", image, "file-test-01")
            self.assertEqual(dispatch.call_count, 1)

    def test_unknown_alias_and_interrupt_never_resubmit(self):
        source = self.source()
        for exception in (subprocess.TimeoutExpired("helper", 30), KeyboardInterrupt()):
            sending._journal("file-test-01").unlink(missing_ok=True)
            with patch.object(files, "prepare", side_effect=self.prepared), \
                 patch.object(files, "preflight_prepared", return_value={"ok": True}), \
                 patch.object(sending, "_dispatch", side_effect=exception) as dispatch:
                if isinstance(exception, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        files.send_file("me", "R:test", source, "file-test-01")
                else:
                    self.assertEqual(files.send_file("me", "R:test", source, "file-test-01")["status"], "submission_unknown")
                self.assertTrue(files.send_file("me", "R:test", source, "file-test-01")["replayed"])
                with self.assertRaisesRegex(ValueError, "QUERY_ORIGINAL"):
                    files.send_file("me", "unique complete name", source, "file-test-02")
                self.assertEqual(dispatch.call_count, 1)

    def test_file_preflight_failure_never_submits(self):
        with patch.object(files, "prepare", side_effect=self.prepared), \
             patch.object(files, "preflight_prepared", return_value={"ok": False}), \
             patch.object(sending, "_dispatch") as dispatch:
            self.assertFalse(files.send_file("me", "R:test", self.source(), "file-test-01")["ok"])
            dispatch.assert_not_called()

    def test_empty_oversized_and_source_symlink_are_rejected(self):
        source = self.source()
        symlink = source.with_name("link.txt")
        symlink.symlink_to(source)
        with self.assertRaises(OSError):
            files.snapshot(symlink)
        source.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "FILE_MUST_BE_REGULAR"):
            files.snapshot(source)
        with source.open("wb") as stream:
            stream.truncate(10 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(ValueError, "FILE_MUST_BE_REGULAR"):
            files.snapshot(source)

    def test_original_file_metadata_type_and_pending_content(self):
        _, metadata = files.snapshot(self.source())
        raw = self.stored(metadata)
        self.assertTrue(files.file_matches(15, raw, {"file": metadata}))
        self.assertFalse(files.file_matches(14, raw, {"file": metadata}))
        for key in ("filename", "size", "md5"):
            changed = metadata | {key: "wrong" if isinstance(metadata[key], str) else metadata[key] + 1}
            self.assertFalse(files.file_matches(15, raw, {"file": changed}))
        self.assertFalse(files.file_matches(15, raw + length_field(10, metadata["md5"].encode()), {"file": metadata}))
        with sqlite3.connect(self.data / "message.db") as conn:
            conn.execute("UPDATE message_table SET content_type=15,content=NULL WHERE message_id=45")
        record = {"account": "me", "account_scope": account("me")["scope"], "chat_id": "R:test",
                  "media_kind": "file", "file": metadata, "local_message_id": 45,
                  "status": "submission_unknown", "ok": False}
        self.assertFalse(sending._reconcile(record)["ok"])

    def test_preflight_verifies_exact_filename_size_and_path(self):
        data, metadata = files.snapshot(self.source())
        prepared = self.prepared("me", "R:test", data, metadata)
        native = {"ok": True, "process_identity_unchanged": True, "native_send_entered": False,
                  "model_released": 1, "info_released": 1}
        raw = length_field(2, metadata["filename"].encode()) + b"\x20" + varint(metadata["size"]) + length_field(100, prepared["text"].encode())
        with patch.object(sending, "_dispatch", return_value=(native, raw)):
            self.assertTrue(files.preflight_prepared(prepared)["ok"])
            for changed in (prepared | {"text": "Z:\\wrong"}, prepared | {"file": metadata | {"size": 999}}):
                self.assertFalse(files.preflight_prepared(changed)["ok"])

    def test_existing_image_request_hash_survives_file_refactor(self):
        source = self.data / "old.png"
        source.write_bytes(png())
        data, metadata = images.snapshot(source)
        original = {"filename": source.name, "format": "png", "width": 1, "height": 1,
                    "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest()}
        old_hash = hashlib.sha256(json.dumps(["image", "me", "R:test", original], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        new_hash = hashlib.sha256(json.dumps(["image", "me", "R:test", metadata], ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(old_hash, new_hash)
