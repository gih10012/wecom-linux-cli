"""Native ordinary-file dispatch with private staging and the shared journal."""

from pathlib import Path

from . import sending, sending_images as assets
from .content import fields


def snapshot(source: Path) -> tuple[bytes, dict]:
    return assets.snapshot_bytes(source, "FILE")


def prepare(name: str, chat: str, data: bytes, metadata: dict) -> dict:
    staged = assets.stage(data, metadata)
    result = sending._prepare(name, chat, sending._winpath(staged))
    result.update(input_kind=8, file_size=metadata["size"], filename=metadata["filename"],
                  file=metadata, staged_file=staged)
    return result


def preflight_prepared(prepared: dict) -> dict:
    result, raw = sending._dispatch(prepared, 1)
    metadata = prepared["file"]
    expected = [(2, 2, metadata["filename"].encode()), (4, 0, metadata["size"]),
                (100, 2, prepared["text"].encode())]
    try:
        payload_matches = fields(raw) == expected
    except ValueError:
        payload_matches = False
    ok = bool(result.get("ok") and result.get("process_identity_unchanged") and payload_matches and
              not result.get("native_send_entered") and result.get("model_released") == 1 and result.get("info_released") == 1)
    return {"ok": ok, "status": "file_construct_verified" if ok else "file_construct_failed",
            "payload_matches": payload_matches, "native": result, "message_send_performed": False,
            "automatic_retry_allowed": False}


def preflight(name: str, chat: str, source: Path) -> dict:
    with sending._lock():
        data, metadata = snapshot(source)
        return preflight_prepared(prepare(name, chat, data, metadata))


def file_matches(kind: int, raw: bytes, record: dict) -> bool:
    if kind != 15:
        return False
    try:
        parsed = fields(raw)
    except ValueError:
        return False
    metadata = record["file"]
    expected = {2: metadata["filename"].encode(), 4: metadata["size"], 10: metadata["md5"].encode()}
    for number, value in expected.items():
        wire = 2 if isinstance(value, bytes) else 0
        if [v for n, w, v in parsed if n == number and w == wire] != [value]:
            return False
    return True


def send_file(name: str, chat: str, source: Path, request_id: str) -> dict:
    return assets.send_asset(name, chat, source, request_id, "file", snapshot, prepare, preflight_prepared)
