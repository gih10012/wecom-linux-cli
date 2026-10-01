"""Read committed SQLite WAL frames with checksums over stored page bytes.

Format: https://www.sqlite.org/fileformat2.html#walformat . This supports
the ciphertext-checksum layout observed in the owner's Windows client;
other cipher WAL layouts fail validation rather than dropping the WAL.
"""

import struct

from .crypto import page_size

MAX_DATABASE_BYTES = 1024 * 1024 * 1024


def checksum(data: bytes, order: str, state=(0, 0)) -> tuple[int, int]:
    a, b = state
    for x, y in struct.iter_unpack(order + "II", data):
        a = (a + x + b) & 0xFFFFFFFF
        b = (b + y + a) & 0xFFFFFFFF
    return a, b


def apply_wal(database: bytes, wal: bytes) -> tuple[bytes, dict]:
    if len(wal) < 32:
        raise ValueError("INCOMPLETE_WAL_HEADER")
    magic, version, size, _, salt1, salt2, check1, check2 = struct.unpack(">8I", wal[:32])
    if magic not in (0x377F0682, 0x377F0683) or version != 3007000:
        raise ValueError("UNSUPPORTED_WAL_HEADER")
    if size != page_size(database) or len(database) % size:
        raise ValueError("WAL_DATABASE_PAGE_SIZE_MISMATCH")
    order = "<" if magic == 0x377F0682 else ">"
    state = checksum(wal[:24], order)
    if state != (check1, check2):
        raise ValueError("WAL_HEADER_CHECKSUM_MISMATCH")
    frame_size = size + 24
    pending, committed = {}, {}
    commit_size = None
    valid_frames = committed_frames = stale_frames = 0
    for offset in range(32, len(wal), frame_size):
        frame = wal[offset:offset + frame_size]
        if len(frame) != frame_size:
            raise ValueError("INCOMPLETE_WAL_FRAME")
        number, truncate, a, b, c1, c2 = struct.unpack(">6I", frame[:24])
        if (a, b) != (salt1, salt2):
            # WAL resets need not truncate the old file. SQLite stops at the
            # first old salt, and never treats later frames as current.
            stale_frames = (len(wal) - offset) // frame_size
            break
        if not number or number * size > MAX_DATABASE_BYTES or truncate * size > MAX_DATABASE_BYTES:
            raise ValueError("INVALID_WAL_PAGE_NUMBER_OR_SIZE")
        state = checksum(frame[:8], order, state)
        state = checksum(frame[24:], order, state)
        if state != (c1, c2):
            raise ValueError("WAL_FRAME_CHECKSUM_MISMATCH")
        valid_frames += 1
        pending[number] = frame[24:]
        if truncate:
            committed.update(pending)
            pending.clear()
            committed = {n: page for n, page in committed.items() if n <= truncate}
            commit_size = truncate
            committed_frames = valid_frames
    result = bytearray(database)
    if commit_size is not None:
        length = commit_size * size
        if len(result) < length:
            result.extend(bytes(length - len(result)))
        del result[length:]
        for number, page in committed.items():
            result[(number - 1) * size:number * size] = page
    return bytes(result), {
        "wal_checksum_verified": True,
        "wal_valid_frames": valid_frames,
        "wal_committed_frames": committed_frames,
        "wal_uncommitted_frames": valid_frames - committed_frames,
        "wal_stale_trailing_frames": stale_frames,
        "wal_commit_pages": commit_size,
    }
