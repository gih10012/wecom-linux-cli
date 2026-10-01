import base64
import unittest

from wecom_linux_cli.content import decode, fields, json_value


def length_field(number, data):
    length = len(data)
    encoded = bytearray()
    while length > 127:
        encoded.append((length & 127) | 128)
        length >>= 7
    encoded.append(length)
    return bytes([number * 8 + 2]) + bytes(encoded) + data


class ContentTests(unittest.TestCase):
    def test_text_preserves_whitespace_single_character_and_emoji(self):
        for text in ("a", "\n中文\n✅\n", "同一段\n同一段", " x "):
            raw = length_field(1, b"\x08\x00" + length_field(2, length_field(1, text.encode())))
            result = decode(0, raw)
            self.assertEqual(result["text"], text)
            self.assertEqual(base64.b64decode(json_value(raw)["data"]), raw)

    def test_unknown_and_malformed_content_remains_lossless(self):
        raw = b"\x00\xff\x01"
        result = decode(9999, raw)
        self.assertIsNone(result["text"])
        self.assertEqual(result["decode_status"], "raw_content_preserved")
        self.assertEqual(base64.b64decode(json_value(raw)["data"]), raw)

    def test_ambiguous_text_is_not_heuristically_joined(self):
        raw = length_field(1, length_field(2, length_field(1, b"first") + length_field(1, b"second")))
        self.assertIsNone(decode(2, raw)["text"])

    def test_partial_varint_and_oversized_field_fail(self):
        for raw in (b"\x80", b"\x0a\xff\x7fhi", b"\x09hi"):
            with self.assertRaises(ValueError):
                fields(raw)
