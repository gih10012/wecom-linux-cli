"""Preserve complete message bytes and decode observed Windows text fields."""

import base64


def varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise ValueError("INCOMPLETE_PROTOBUF")
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            raise ValueError("INVALID_PROTOBUF_VARINT")
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise ValueError("INVALID_PROTOBUF_VARINT")


def fields(data: bytes) -> list[tuple[int, int, object]]:
    result, offset = [], 0
    while offset < len(data):
        tag, offset = varint(data, offset)
        number, wire = tag >> 3, tag & 7
        if not 0 < number < 2**29:
            raise ValueError("INVALID_PROTOBUF_FIELD")
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            value = data[offset:offset + size]
            offset += size
            if len(value) != size:
                raise ValueError("INCOMPLETE_PROTOBUF")
        elif wire == 2:
            size, offset = varint(data, offset)
            value = data[offset:offset + size]
            offset += size
            if len(value) != size:
                raise ValueError("INCOMPLETE_PROTOBUF")
        else:
            raise ValueError("UNSUPPORTED_PROTOBUF_WIRE_TYPE")
        result.append((number, wire, value))
    return result


def nested(data: bytes, path: tuple[int, ...]) -> bytes:
    for number in path:
        matches = [value for n, wire, value in fields(data) if n == number and wire == 2]
        if len(matches) != 1:
            raise ValueError("AMBIGUOUS_OR_MISSING_TEXT_FIELD")
        data = matches[0]
    return data


def json_value(value):
    if isinstance(value, bytes):
        return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
    return value


def decode(kind: int, raw) -> dict:
    result = {"text": None, "content_type": kind, "media_downloaded": False}
    if isinstance(raw, str):
        result.update(text=raw, decode_status="stored_text")
        return result
    if raw is None:
        result["decode_status"] = "empty"
        return result
    data = bytes(raw)
    try:
        parsed = fields(data)
        result["fields"] = [{"number": n, "wire": wire, "value": json_value(v)}
                            for n, wire, v in parsed]
        if kind in (0, 2):
            # Confirmed against the owner's Windows 5.0.11 real messages.
            # Do not heuristically join binary strings into a fake body.
            result.update(text=nested(data, (1, 2, 1)).decode("utf-8"),
                          decode_status="windows_text_1_2_1")
        elif kind == 40:
            # Native voice-call bubble, verified against both opposite clients.
            # The display label is field3; preserve all other protocol fields.
            result.update(text=nested(data, (3,)).decode("utf-8"),
                          decode_status="windows_voice_bubble_3")
        else:
            result["decode_status"] = "raw_fields_preserved"
            if kind in (14, 15, 16):
                names = [v for n, wire, v in parsed if n == 2 and wire == 2]
                if len(names) == 1:
                    try:
                        result["filename"] = names[0].decode("utf-8")
                    except UnicodeError:
                        pass
    except (ValueError, UnicodeError):
        result["decode_status"] = "raw_content_preserved"
    return result
