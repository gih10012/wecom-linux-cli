import json
import sqlite3
import struct
import subprocess
import unittest
from unittest.mock import patch

import test_messages
from test_media import varint, length_field
from wecom_linux_cli import sending, sending_stickers as stickers, sending_images as assets
from wecom_linux_cli.messages import account


def gif(frames=2):
    # Two-entry global palette, 1x1 LZW image, optional animation control.
    frame = b"\x21\xf9\x04\0\x0a\0\0\0\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0) + b"\x02\x02\x44\x01\0"
    return b"GIF89a" + struct.pack("<HHBBB", 1, 1, 128, 0, 0) + b"\0\0\0\xff\xff\xff" + frame * frames + b";"


class GifValidationTests(unittest.TestCase):
    def test_static_and_animated_complete_files(self):
        self.assertEqual(stickers.dimensions(gif(1)), (1, 1, 1))
        self.assertEqual(stickers.dimensions(gif(3)), (1, 1, 3))

    def test_truncation_at_every_boundary_and_trailing_bytes(self):
        data = gif()
        for length in range(len(data)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                stickers.dimensions(data[:length])
        for invalid in (data + b"extra", gif(0), data[:19] + b"\xff" + data[20:]):
            with self.assertRaises(ValueError):
                stickers.dimensions(invalid)

    def test_bad_frame_bounds_code_size_and_extension(self):
        for offset, value in ((28, 2), (37, 1), (21, 3), (6, 0)):
            data = bytearray(gif())
            data[offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                stickers.dimensions(bytes(data))


class StickerSendTests(unittest.TestCase):
    setUp = test_messages.MessageReadTests.setUp
    tearDown = test_messages.MessageReadTests.tearDown

    def source(self):
        source = self.data / "中文表情.gif"
        source.write_bytes(gif())
        return source

    def prepared(self, name, chat, data, metadata):
        return {"value": account(name), "chat": "R:test", "before": [{"pid": 123}],
                "text": "Z:\\staged\\" + metadata["filename"], "sticker": metadata,
                "staged_sticker": assets.stage(data, metadata)}

    def stored(self, metadata):
        return (b"\x10\x02" + length_field(6, metadata["md5"].encode()) +
                b"\x38" + varint(metadata["width"]) + b"\x40" + varint(metadata["height"]) + b"\x58\x02")

    def dispatched(self, prepared, mode):
        record = json.loads(sending._journal("sticker-test-01").read_text())
        self.assertEqual(record["status"], "submission_unknown")
        self.assertFalse(record["automatic_retry_allowed"])
        with sqlite3.connect(self.data / "message.db") as conn:
            conn.execute("INSERT INTO message_table VALUES(46,987,123,?,29,101,?)",
                         (prepared["chat"], self.stored(prepared["sticker"])))
        return {"ok": True, "state": 2, "native_send_entered": True,
                "send_returned": True, "ids": [1, 0, 46, 0]}, b""

    def test_replay_and_changed_animation_or_filename_conflict(self):
        source = self.source()
        with patch.object(stickers, "prepare", side_effect=self.prepared), \
             patch.object(stickers, "preflight_prepared", return_value={"ok": True}), \
             patch.object(sending, "_dispatch", side_effect=self.dispatched) as dispatch:
            self.assertTrue(stickers.send_sticker("me", "R:test", source, "sticker-test-01")["ok"])
            self.assertTrue(stickers.send_sticker("me", "R:test", source, "sticker-test-01")["replayed"])
            renamed = source.with_name("改名.gif")
            renamed.write_bytes(source.read_bytes())
            with self.assertRaisesRegex(ValueError, "PAYLOAD_CONFLICT"):
                stickers.send_sticker("me", "R:test", renamed, "sticker-test-01")
            source.write_bytes(gif(3))
            with self.assertRaisesRegex(ValueError, "PAYLOAD_CONFLICT"):
                stickers.send_sticker("me", "R:test", source, "sticker-test-01")
            self.assertEqual(dispatch.call_count, 1)

    def test_unknown_alias_and_interrupt_do_not_submit_again(self):
        source = self.source()
        for exception in (subprocess.TimeoutExpired("helper", 30), KeyboardInterrupt()):
            sending._journal("sticker-test-01").unlink(missing_ok=True)
            with patch.object(stickers, "prepare", side_effect=self.prepared), \
                 patch.object(stickers, "preflight_prepared", return_value={"ok": True}), \
                 patch.object(sending, "_dispatch", side_effect=exception) as dispatch:
                if isinstance(exception, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        stickers.send_sticker("me", "R:test", source, "sticker-test-01")
                else:
                    self.assertEqual(stickers.send_sticker("me", "R:test", source, "sticker-test-01")["status"], "submission_unknown")
                self.assertTrue(stickers.send_sticker("me", "R:test", source, "sticker-test-01")["replayed"])
                with self.assertRaisesRegex(ValueError, "QUERY_ORIGINAL"):
                    stickers.send_sticker("me", "complete unique name", source, "sticker-test-02")
                self.assertEqual(dispatch.call_count, 1)

    def test_missing_content_wrong_media_dimensions_or_duplicate_md5_stay_unknown(self):
        _, metadata = stickers.snapshot(self.source())
        raw = self.stored(metadata)
        self.assertTrue(stickers.sticker_matches(29, raw, {"sticker": metadata}))
        self.assertFalse(stickers.sticker_matches(15, raw, {"sticker": metadata}))
        for key in ("md5", "width", "height"):
            changed = metadata | {key: "wrong" if key == "md5" else 2}
            self.assertFalse(stickers.sticker_matches(29, raw, {"sticker": changed}))
        self.assertFalse(stickers.sticker_matches(29, raw + length_field(6, metadata["md5"].encode()), {"sticker": metadata}))
        with sqlite3.connect(self.data / "message.db") as conn:
            conn.execute("UPDATE message_table SET content_type=29,content=NULL WHERE message_id=45")
        record = {"account": "me", "account_scope": account("me")["scope"], "chat_id": "R:test",
                  "media_kind": "sticker", "sticker": metadata, "local_message_id": 45,
                  "status": "submission_unknown", "ok": False}
        self.assertFalse(sending._reconcile(record)["ok"])

    def test_extension_mismatch_is_rejected(self):
        source = self.source().with_suffix(".png")
        source.write_bytes(gif())
        with self.assertRaisesRegex(ValueError, "EXTENSION"):
            stickers.snapshot(source)
