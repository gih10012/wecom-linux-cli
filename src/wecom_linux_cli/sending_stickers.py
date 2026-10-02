"""Native GIF EmotionMessage dispatch through the shared durable journal."""

import struct
from pathlib import Path

from . import sending, sending_images as assets
from .content import fields


def dimensions(data: bytes) -> tuple[int, int, int]:
    if len(data) < 14 or data[:6] not in (b"GIF87a", b"GIF89a"):
        raise ValueError("GIF_STICKER_REQUIRED")
    width, height = struct.unpack_from("<HH", data, 6)
    if not (0 < width <= 32768 and 0 < height <= 32768 and width * height <= 64_000_000):
        raise ValueError("INVALID_OR_OVERSIZED_GIF_DIMENSIONS")
    offset = 13 + (3 * (2 << (data[10] & 7)) if data[10] & 128 else 0)
    frames = 0

    def subblocks(position):
        while position < len(data):
            size = data[position]
            position += 1
            if not size:
                return position
            position += size
        raise ValueError("TRUNCATED_GIF_BLOCKS")

    while offset < len(data):
        marker = data[offset]
        offset += 1
        if marker == 0x3B:
            if offset != len(data) or not frames:
                raise ValueError("INVALID_GIF_TRAILER_OR_NO_FRAMES")
            return width, height, frames
        if marker == 0x21:
            if offset + 1 >= len(data):
                break
            label = data[offset]
            offset += 1
            if label in (0xF9, 0xFF, 0x01) and data[offset] != {0xF9: 4, 0xFF: 11, 0x01: 12}[label]:
                raise ValueError("INVALID_GIF_EXTENSION")
            offset = subblocks(offset)
        elif marker == 0x2C:
            if offset + 9 > len(data):
                break
            left, top, w, h, packed = struct.unpack_from("<HHHHB", data, offset)
            if not w or not h or left + w > width or top + h > height:
                raise ValueError("INVALID_GIF_FRAME_DIMENSIONS")
            offset += 9 + (3 * (2 << (packed & 7)) if packed & 128 else 0)
            if offset >= len(data) or not 2 <= data[offset] <= 8:
                raise ValueError("INVALID_GIF_LZW_CODE_SIZE")
            offset = subblocks(offset + 1)
            frames += 1
            if frames > 2000:
                raise ValueError("TOO_MANY_GIF_FRAMES")
        else:
            raise ValueError("INVALID_GIF_BLOCK")
    raise ValueError("TRUNCATED_GIF_OR_MISSING_TRAILER")


def snapshot(source: Path) -> tuple[bytes, dict]:
    data, metadata = assets.snapshot_bytes(source, "STICKER")
    width, height, frames = dimensions(data)
    if source.suffix.lower() != ".gif":
        raise ValueError("GIF_STICKER_EXTENSION_REQUIRED")
    return data, metadata | {"format": "gif", "width": width, "height": height, "frames": frames}


def prepare(name: str, chat: str, data: bytes, metadata: dict) -> dict:
    staged = assets.stage(data, metadata)
    result = sending._prepare(name, chat, sending._winpath(staged))
    result.update(input_kind=29, width=metadata["width"], height=metadata["height"],
                  filename=metadata["filename"], sticker=metadata, staged_sticker=staged)
    return result


def preflight_prepared(prepared: dict) -> dict:
    result, raw = sending._dispatch(prepared, 1)
    m = prepared["sticker"]
    expected = [(1, 2, prepared["text"].encode()), (2, 0, 2), (3, 2, b""), (4, 0, 0),
                (5, 2, b""), (6, 2, b""), (7, 0, m["width"]), (8, 0, m["height"]),
                (9, 2, b""), (10, 2, b""), (11, 0, 2), (12, 2, b""), (17, 2, b""), (18, 2, b"")]
    try:
        payload_matches = fields(raw) == expected
    except ValueError:
        payload_matches = False
    ok = bool(result.get("ok") and result.get("process_identity_unchanged") and payload_matches and
              not result.get("native_send_entered") and result.get("model_released") == 1 and result.get("info_released") == 1)
    return {"ok": ok, "status": "sticker_construct_verified" if ok else "sticker_construct_failed",
            "payload_matches": payload_matches, "native": result, "message_send_performed": False,
            "automatic_retry_allowed": False}


def preflight(name: str, chat: str, source: Path) -> dict:
    with sending._lock():
        data, metadata = snapshot(source)
        return preflight_prepared(prepare(name, chat, data, metadata))


def sticker_matches(kind: int, raw: bytes, record: dict) -> bool:
    if kind != 29:
        return False
    try:
        parsed = fields(raw)
    except ValueError:
        return False
    metadata = record["sticker"]
    expected = {2: 2, 6: metadata["md5"].encode(), 7: metadata["width"], 8: metadata["height"], 11: 2}
    return all([v for n, w, v in parsed if n == number and w == (2 if isinstance(value, bytes) else 0)] == [value]
               for number, value in expected.items())


def send_sticker(name: str, chat: str, source: Path, request_id: str) -> dict:
    return assets.send_asset(name, chat, source, request_id, "sticker", snapshot, prepare, preflight_prepared)
