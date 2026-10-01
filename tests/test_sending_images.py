import hashlib
import json
import sqlite3
import struct
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import test_messages
from test_media import png, varint, length_field
from wecom_linux_cli import sending, sending_images as images
from wecom_linux_cli.messages import account


class ImageSendTests(unittest.TestCase):
    setUp = test_messages.MessageReadTests.setUp
    tearDown = test_messages.MessageReadTests.tearDown

    def source(self):
        path = self.data / "测试图片.png"
        path.write_bytes(png())
        return path

    def prepared(self, name, chat, data, image):
        return {"value": account(name), "chat": "R:test", "before": [{"pid": 123}],
                "text": "Z:\\staged\\" + image["filename"], "image": image,
                "staged_image": images.stage(data, image)}

    def stored(self, image):
        return b"".join((length_field(2, image["filename"].encode()),
                         b"\x20" + varint(image["size"]), b"\x28" + varint(image["width"]),
                         b"\x30" + varint(image["height"]), length_field(10, image["md5"].encode())))

    def dispatched(self, prepared, mode):
        journal = json.loads(sending._journal("image-test-01").read_text())
        self.assertEqual(journal["status"], "submission_unknown")
        self.assertFalse(journal["automatic_retry_allowed"])
        with sqlite3.connect(self.data / "message.db") as conn:
            conn.execute("INSERT INTO message_table VALUES(46,987,123,?,14,101,?)",
                         (prepared["chat"], self.stored(prepared["image"])))
        return {"ok": True, "state": 2, "native_send_entered": True,
                "send_returned": True, "ids": [1, 0, 46, 0]}, b""

    def test_replay_content_and_filename_conflicts(self):
        source = self.source()
        with patch.object(images, "prepare", side_effect=self.prepared), \
             patch.object(images, "preflight_prepared", return_value={"ok": True}), \
             patch.object(sending, "_dispatch", side_effect=self.dispatched) as dispatch:
            result = images.send_image("me", "R:test", source, "image-test-01")
            self.assertTrue(result["ok"])
            self.assertTrue(images.send_image("me", "R:test", source, "image-test-01")["replayed"])
            changed = source.with_name("改名.png")
            changed.write_bytes(source.read_bytes())
            with self.assertRaisesRegex(ValueError, "PAYLOAD_CONFLICT"):
                images.send_image("me", "R:test", changed, "image-test-01")
            self.assertEqual(dispatch.call_count, 1)
            source.write_bytes(source.read_bytes() + b"different")
            with self.assertRaisesRegex(ValueError, "PAYLOAD_CONFLICT"):
                images.send_image("me", "R:test", source, "image-test-01")

    def test_unknown_and_alias_never_dispatch_again(self):
        source = self.source()
        with patch.object(images, "prepare", side_effect=self.prepared), \
             patch.object(images, "preflight_prepared", return_value={"ok": True}), \
             patch.object(sending, "_dispatch", side_effect=subprocess.TimeoutExpired("helper", 30)) as dispatch:
            result = images.send_image("me", "R:test", source, "image-test-01")
            self.assertEqual(result["status"], "submission_unknown")
            self.assertTrue(images.send_image("me", "R:test", source, "image-test-01")["replayed"])
            with self.assertRaisesRegex(ValueError, "QUERY_ORIGINAL"):
                images.send_image("me", "precise unique name", source, "image-test-02")
            self.assertEqual(dispatch.call_count, 1)

    def test_interrupt_has_a_durable_unknown_journal(self):
        source = self.source()
        with patch.object(images, "prepare", side_effect=self.prepared), \
             patch.object(images, "preflight_prepared", return_value={"ok": True}), \
             patch.object(sending, "_dispatch", side_effect=KeyboardInterrupt) as dispatch:
            with self.assertRaises(KeyboardInterrupt):
                images.send_image("me", "R:test", source, "image-test-01")
            self.assertEqual(images.send_image("me", "R:test", source, "image-test-01")["status"], "submission_unknown")
            self.assertEqual(dispatch.call_count, 1)

    def test_preflight_failure_does_not_submit(self):
        with patch.object(images, "prepare", side_effect=self.prepared), \
             patch.object(images, "preflight_prepared", return_value={"ok": False}), \
             patch.object(sending, "_dispatch") as dispatch:
            self.assertFalse(images.send_image("me", "R:test", self.source(), "image-test-01")["ok"])
            dispatch.assert_not_called()

    def test_staged_copy_is_private_and_survives_original_changes(self):
        source = self.source()
        data, info = images.snapshot(source)
        staged = images.stage(data, info)
        source.write_bytes(b"modified later")
        self.assertEqual(staged.read_bytes(), data)
        self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
        self.assertEqual(images.stage(data, info), staged)
        staged.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "STAGED_IMAGE_CONFLICT"):
            images.stage(data, info)

    def test_source_symlink_and_windows_invalid_names_rejected(self):
        source = self.source()
        symlink = source.with_name("symlink.png")
        symlink.symlink_to(source)
        with self.assertRaises(OSError):
            images.snapshot(symlink)
        for name in ("CON.png", "a:b.png", "trailing.png "):
            invalid = source.with_name(name)
            invalid.write_bytes(png())
            with self.assertRaisesRegex(ValueError, "FILENAME"):
                images.snapshot(invalid)

    def test_original_metadata_must_match_each_field_and_type(self):
        _, image = images.snapshot(self.source())
        raw = self.stored(image)
        self.assertTrue(images.image_matches(14, raw, {"image": image}))
        self.assertFalse(images.image_matches(101, raw, {"image": image}))
        for key in ("filename", "size", "width", "height", "md5"):
            changed = image | {key: "wrong" if isinstance(image[key], str) else image[key] + 1}
            self.assertFalse(images.image_matches(14, raw, {"image": changed}))
        self.assertFalse(images.image_matches(14, raw + length_field(10, image["md5"].encode()), {"image": image}))

    def test_preflight_rejects_wrong_path_and_size(self):
        _, image = images.snapshot(self.source())
        prepared = self.prepared("me", "R:test", png(), image)
        native = {"ok": True, "process_identity_unchanged": True, "native_send_entered": False,
                  "model_released": 1, "info_released": 1}
        correct = self.stored(image)
        with patch.object(sending, "_dispatch", return_value=(native, correct)):
            self.assertFalse(images.preflight_prepared(prepared)["ok"])

    def test_pending_null_content_stays_unknown_in_send_status(self):
        _, image = images.snapshot(self.source())
        with sqlite3.connect(self.data / "message.db") as conn:
            conn.execute("UPDATE message_table SET content=NULL WHERE message_id=45")
        value = account("me")
        record = {"account": "me", "account_scope": value["scope"], "chat_id": "R:test",
                  "media_kind": "image", "image": image, "local_message_id": 45,
                  "status": "submission_unknown", "ok": False}
        self.assertFalse(sending._reconcile(record)["ok"])


class ImageHeaderTests(unittest.TestCase):
    def test_png_bad_crc_and_dimension_limit(self):
        self.assertEqual(images.dimensions(png()), ("png", 1, 1))
        damaged = bytearray(png())
        damaged[16] ^= 1
        with self.assertRaisesRegex(ValueError, "PNG_HEADER"):
            images.dimensions(bytes(damaged))

    def test_jpeg_uses_sof_not_exif_thumbnail_and_rejects_truncated_segment(self):
        jpeg = (b"\xff\xd8\xff\xe1\0\x04ab\xff\xc2\0\x0b\x08" +
                struct.pack(">HH", 360, 640) + b"\x01\x01\x11\0\xff\xd9")
        self.assertEqual(images.dimensions(jpeg), ("jpeg", 640, 360))
        for invalid in (jpeg[:8] + b"\xff\xd9", b"\xff\xd8\xff\xc0\0\x0b\x08\0\0\0\0abc\xff\xd9"):
            with self.assertRaisesRegex(ValueError, "DIMENSIONS"):
                images.dimensions(invalid)
