import ctypes
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wecom_linux_cli.crypto import page_iv
from wecom_linux_cli.keys import search_library


class NativeKeySearchTests(unittest.TestCase):
    def test_key_without_length_heuristic_and_chunk_overlap(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"XDG_STATE_HOME": root}):
            lib = search_library()
            encrypted = (Path(__file__).parent / "fixtures/sqlite3mc-aes128.enc").read_bytes()[:4096]
            memory = bytearray(65568)
            memory[65532:65548] = bytes(range(16))
            buffer = ctypes.create_string_buffer(bytes(memory))
            page = ctypes.create_string_buffer(encrypted)
            iv = ctypes.create_string_buffer(page_iv(1))
            out = ctypes.create_string_buffer(16)
            self.assertEqual(lib.find_key(buffer, len(memory), page, iv, out), 1)
            self.assertEqual(out.raw, bytes(range(16)))
            bad = ctypes.create_string_buffer(bytes(len(memory)))
            self.assertEqual(lib.find_key(bad, len(memory), page, iv, out), 0)
