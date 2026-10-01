"""Read wxSQLite3 AES-128 pages; never modify the client's databases.

The format is documented by the MIT-licensed SQLite3 Multiple Ciphers
implementation (utelle/SQLite3MultipleCiphers, cipher_wxaes128.c and
codec_algos.c). The input key is the already-derived 16-byte cipher key,
not an account password and not a SQLCipher key.
"""

import hashlib
import struct

from Crypto.Cipher import AES

SQLITE_HEADER = b"SQLite format 3\0"


def page_size(header: bytes) -> int:
    if len(header) < 24 or header[21:24] != b"\x40\x20\x20":
        raise ValueError("UNSUPPORTED_DATABASE_HEADER")
    size = int.from_bytes(header[16:18], "big")
    size = 65536 if size == 1 else size
    if size < 512 or size > 65536 or size & (size - 1):
        raise ValueError("INVALID_PAGE_SIZE")
    return size


def page_key(raw_key: bytes, number: int) -> bytes:
    if len(raw_key) != 16 or not 1 <= number <= 0xFFFFFFFF:
        raise ValueError("INVALID_KEY_OR_PAGE_NUMBER")
    return hashlib.md5(raw_key + struct.pack("<I", number) + b"sAlT").digest()


def page_iv(number: int) -> bytes:
    state = number + 1
    words = []
    for _ in range(4):
        q, r = divmod(state, 52774)
        state = 40692 * r - 3791 * q
        if state < 0:
            state += 2147483399
        words.append(state)
    return hashlib.md5(struct.pack("<4I", *words)).digest()


def verify_key(key: bytes, encrypted_first_page: bytes) -> bool:
    try:
        size = page_size(encrypted_first_page)
        if len(encrypted_first_page) != size:
            return False
        # Validate existing plaintext against decrypted bytes. Restoring the
        # magic unconditionally would incorrectly accept every candidate key.
        block = encrypted_first_page[8:16] + encrypted_first_page[24:32]
        first = AES.new(page_key(key, 1), AES.MODE_CBC, page_iv(1)).decrypt(block)
        return first[:8] == encrypted_first_page[16:24]
    except ValueError:
        return False


def decrypt_page(key: bytes, data: bytes, number: int) -> bytes:
    if len(data) < 512 or len(data) % 16:
        raise ValueError("INCOMPLETE_DATABASE_PAGE")
    cipher = AES.new(page_key(key, number), AES.MODE_CBC, page_iv(number))
    if number != 1:
        return cipher.decrypt(data)
    if len(data) != page_size(data) or not verify_key(key, data):
        raise ValueError("DATABASE_KEY_MISMATCH")
    tail = cipher.decrypt(data[8:16] + data[24:])
    return SQLITE_HEADER + tail


def decrypt_bytes(key: bytes, data: bytes) -> bytes:
    size = page_size(data)
    if len(data) % size or not data:
        raise ValueError("INCOMPLETE_DATABASE_FILE")
    if not verify_key(key, data[:size]):
        raise ValueError("DATABASE_KEY_MISMATCH")
    return b"".join(
        decrypt_page(key, data[i:i + size], i // size + 1)
        for i in range(0, len(data), size)
    )
