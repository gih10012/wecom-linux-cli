"""Native article/mini-program cards; preserved protobuf and editable appmsg XML."""

import base64
import hashlib
import json
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from . import sending, sending_images as assets
from .content import fields
from .database import open_snapshot
from .messages import account, names
from .state import read_private

MAX = 65536
APP_TYPES = {13: 5, 78: 33}


def _varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _encode(parsed):
    result = bytearray()
    for number, wire, value in parsed:
        result.extend(_varint(number * 8 + wire))
        if wire == 0:
            result.extend(_varint(value))
        elif wire == 2:
            result.extend(_varint(len(value)))
            result.extend(value)
        else:
            result.extend(value)
    return bytes(result)


def _one(parsed, number, wire=2, default=b""):
    matches = [(w, v) for n, w, v in parsed if n == number]
    if len(matches) > 1 or (matches and matches[0][0] != wire):
        raise ValueError("AMBIGUOUS_CARD_FIELD")
    return matches[0][1] if matches else default


def _replace(parsed, number, value, wire=2):
    if sum(n == number for n, w, v in parsed) > 1 or any(n == number and w != wire for n, w, v in parsed):
        raise ValueError("AMBIGUOUS_CARD_FIELD")
    result = [(n, w, value if n == number else v) for n, w, v in parsed]
    if not any(n == number for n, w, v in result):
        result.append((number, wire, value))
    return sorted(result, key=lambda item: item[0])


def _body(kind, raw):
    if kind not in APP_TYPES or not 0 < len(raw) <= MAX:
        raise ValueError("ARTICLE_OR_MINIPROGRAM_CARD_REQUIRED")
    parsed = fields(raw)
    if kind == 78:
        inner = _one(parsed, 107)
        if not inner:
            raise ValueError("MISSING_NATIVE_MINIPROGRAM_METADATA")
        parsed = fields(inner)
        if not all(_one(parsed, n) for n in (1, 2, 3)):
            raise ValueError("MINIPROGRAM_IDENTITY_AND_PAGE_REQUIRED")
        if not _one(parsed, 7).decode("utf-8").strip():
            raise ValueError("CARD_TITLE_REQUIRED")
    elif not _one(parsed, 3).decode("utf-8").strip() or not _one(parsed, 1).startswith((b"https://", b"http://")):
        raise ValueError("CARD_TITLE_AND_HTTP_URL_REQUIRED")
    return parsed


def _source(name, chat, message_id):
    if not isinstance(message_id, int) or message_id <= 0:
        raise ValueError("POSITIVE_MESSAGE_ID_REQUIRED")
    value = account(name)
    _, chats, _ = names(value)
    if chat not in chats:
        matches = [cid for cid, label in chats.items() if label == chat]
        if len(matches) > 1:
            raise ValueError("AMBIGUOUS_CHAT_NAME_USE_EXACT_ID")
        if matches:
            chat = matches[0]
    with open_snapshot(value["data_dir"] / "message.db", value["key_file"]) as (conn, evidence):
        rows = conn.execute("SELECT content_type,content FROM message_table WHERE conversation_id=? AND message_id=?",
                            (chat, message_id)).fetchall()
    if len(rows) != 1 or not isinstance(rows[0][1], (bytes, bytearray, memoryview)):
        raise ValueError("EXACT_SOURCE_MESSAGE_NOT_FOUND")
    kind, raw = rows[0][0], bytes(rows[0][1])
    _body(kind, raw)
    identity = {"account_scope": value["scope"], "chat_id": chat, "message_id": message_id}
    return kind, raw, identity


def _xml(kind, raw):
    parsed = _body(kind, raw)
    root = ET.Element("msg")
    app = ET.SubElement(root, "appmsg")
    def tag(parent, name, value):
        ET.SubElement(parent, name).text = value.decode("utf-8") if isinstance(value, bytes) else str(value)
    tag(app, "type", APP_TYPES[kind])
    if kind == 13:
        for label, number in (("title", 3), ("des", 4), ("url", 1), ("thumburl", 2)):
            if any(n == number for n, w, v in parsed):
                tag(app, label, _one(parsed, number))
    else:
        for label, number in (("title", 7), ("des", 8), ("sourcedisplayname", 10)):
            if any(n == number for n, w, v in parsed):
                tag(app, label, _one(parsed, number))
        weapp = ET.SubElement(app, "weappinfo")
        for label, number in (("username", 1), ("appid", 2), ("pagepath", 3)):
            tag(weapp, label, _one(parsed, number))
        if any(n == 6 for n, w, v in parsed):
            tag(weapp, "weappiconurl", _one(parsed, 6))
        tag(weapp, "type", _one(parsed, 4, 0, 2))
    native = ET.SubElement(root, "wecom-native", {"version": "1", "content-type": str(kind),
                         "encoding": "base64", "sha256": hashlib.sha256(raw).hexdigest()})
    native.text = base64.b64encode(raw).decode("ascii")
    return ET.tostring(root, encoding="unicode")


def message_xml(name, chat, message_id):
    kind, raw, identity = _source(name, chat, message_id)
    return {"ok": True, "account": name, **identity, "content_type": kind, "xml": _xml(kind, raw),
            "native_fields_preserved": True, "message_send_performed": False}


def parse_xml(data):
    if not 0 < len(data) <= MAX or b"\0" in data:
        raise ValueError("XML_MUST_BE_1_TO_65536_UTF8_BYTES_WITHOUT_NUL")
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("UTF8_XML_REQUIRED") from exc
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("XML_DTD_AND_ENTITIES_FORBIDDEN")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("INVALID_CARD_XML") from exc
    if root.tag != "msg" or len(root.findall("appmsg")) != 1 or len(list(root.iter())) > 2000:
        raise ValueError("EXACT_MSG_APPMSG_REQUIRED")
    app = root.find("appmsg")
    def scalar(parent, label, required=False):
        nodes = parent.findall(label)
        if len(nodes) > 1 or (nodes and list(nodes[0])):
            raise ValueError("AMBIGUOUS_CARD_XML_FIELD")
        value = (nodes[0].text or "") if nodes else ""
        if required and not value.strip():
            raise ValueError("MISSING_CARD_XML_" + label.upper())
        return value
    app_type = scalar(app, "type", True)
    if app_type not in ("5", "33"):
        raise ValueError("ARTICLE_OR_MINIPROGRAM_XML_REQUIRED")
    kind = 13 if app_type == "5" else 78
    native = root.findall("wecom-native")
    if len(native) > 1:
        raise ValueError("AMBIGUOUS_NATIVE_CARD_PAYLOAD")
    raw = b""
    if native:
        node = native[0]
        if node.get("version") != "1" or node.get("encoding") != "base64" or node.get("content-type") != str(kind) or list(node):
            raise ValueError("INVALID_NATIVE_CARD_PAYLOAD_METADATA")
        try:
            raw = base64.b64decode(node.text or "", validate=True)
        except ValueError as exc:
            raise ValueError("INVALID_NATIVE_CARD_BASE64") from exc
        if hashlib.sha256(raw).hexdigest() != node.get("sha256"):
            raise ValueError("NATIVE_CARD_PAYLOAD_HASH_MISMATCH")
        _body(kind, raw)
    elif kind == 78:
        raise ValueError("MINIPROGRAM_XML_REQUIRES_EXPORTED_NATIVE_PAYLOAD")
    parsed = _body(kind, raw) if raw else []
    if kind == 13:
        mappings = (("title", 3, True), ("des", 4, False), ("url", 1, True), ("thumburl", 2, False))
    else:
        mappings = (("title", 7, True), ("des", 8, False), ("sourcedisplayname", 10, False))
    for label, number, required in mappings:
        if app.find(label) is not None or required:
            parsed = _replace(parsed, number, scalar(app, label, required).encode("utf-8"))
    if kind == 78:
        if len(app.findall("weappinfo")) != 1:
            raise ValueError("EXACT_WEAPPINFO_REQUIRED")
        weapp = app.find("weappinfo")
        for label, number in (("username", 1), ("appid", 2), ("pagepath", 3)):
            parsed = _replace(parsed, number, scalar(weapp, label, True).encode("utf-8"))
        if weapp.find("weappiconurl") is not None:
            parsed = _replace(parsed, 6, scalar(weapp, "weappiconurl").encode("utf-8"))
        # Real native fields and share/upload metadata stay with the source card.
        # A different app/page requires its actual source, not borrowed tickets.
        original = _body(kind, raw)
        if any(_one(parsed, n) != _one(original, n) for n in (1, 2, 3)):
            raise ValueError("MINIPROGRAM_IDENTITY_CHANGED_REQUIRES_ACTUAL_SOURCE")
        if scalar(weapp, "type", True) != str(_one(original, 4, 0, 2)):
            raise ValueError("MINIPROGRAM_TYPE_CHANGED_REQUIRES_ACTUAL_SOURCE")
        parsed = _replace(fields(raw), 107, _encode(parsed))
    raw = _encode(parsed)
    _body(kind, raw)
    return kind, raw


def _prepare(name, chat, kind, raw):
    _body(kind, raw)
    prepared = sending._prepare(name, chat, "native card payload")
    prepared.update(input_kind=kind, payload=raw)
    return prepared


def _check(prepared):
    result, raw = sending._dispatch(prepared, 1)
    try:
        matches = fields(raw) == fields(prepared["payload"])
    except ValueError:
        matches = False
    ok = bool(result.get("ok") and result.get("process_identity_unchanged") and matches and
              not result.get("native_send_entered") and result.get("model_released") == 1 and result.get("info_released") == 1)
    return {"ok": ok, "status": "card_construct_verified" if ok else "card_construct_failed",
            "payload_matches": matches, "native": result, "message_send_performed": False,
            "automatic_retry_allowed": False}


def card_matches(kind, raw, record):
    metadata = record["card"]
    if kind != metadata["content_type"]:
        return False
    try:
        actual = _body(kind, raw)
        expected = fields(base64.b64decode(metadata["payload"], validate=True))
        if kind == 78:
            return actual == fields(_one(expected, 107))
        # The native uploader may normalize thumbnail URLs and extra metadata.
        return all(_one(actual, n) == _one(expected, n) for n in (1, 3, 4))
    except (ValueError, UnicodeError):
        return False


def _send(name, chat, kind, raw, request_id, action, source):
    path = sending._journal(request_id)
    with sending._lock():
        metadata = {"content_type": kind, "payload": base64.b64encode(raw).decode(),
                    "sha256": hashlib.sha256(raw).hexdigest(), "action": action, "source": source}
        request_hash = hashlib.sha256(json.dumps(["card", name, chat, metadata], ensure_ascii=False,
                                                separators=(",", ":")).encode()).hexdigest()
        if path.exists():
            record = read_private(path)
            if record["request_hash"] != request_hash:
                raise ValueError("REQUEST_ID_PAYLOAD_CONFLICT")
            record = sending._reconcile(record)
            sending._persist(path, record)
            return {**record, "replayed": True}
        for previous in path.parent.glob("*.json"):
            old = read_private(previous)
            if old.get("request_hash") == request_hash and old.get("status") == "submission_unknown":
                raise ValueError("SAME_OPERATION_UNKNOWN_QUERY_ORIGINAL_REQUEST")
        prepared = _prepare(name, chat, kind, raw)
        operation_hash = hashlib.sha256(json.dumps(
            ["card", prepared["value"]["scope"], prepared["chat"], kind, metadata["sha256"]],
            separators=(",", ":")).encode()).hexdigest()
        for previous in path.parent.glob("*.json"):
            old = read_private(previous)
            if old.get("operation_hash") == operation_hash and old.get("status") == "submission_unknown":
                raise ValueError("SAME_OPERATION_UNKNOWN_QUERY_ORIGINAL_REQUEST")
        checked = _check(prepared)
        if not checked["ok"]:
            return checked
        record = {"ok": False, "status": "submission_unknown", "request_id": request_id,
                  "request_hash": request_hash, "operation_hash": operation_hash, "account": name,
                  "account_scope": prepared["value"]["scope"], "chat_id": prepared["chat"],
                  "media_kind": "card", "card": metadata, "preflight": checked,
                  "process": prepared["before"][0], "created_at": time.time(),
                  "automatic_retry_allowed": False, "native_submission_entered": None,
                  "message_send_performed": None, "local_history_integrated": False,
                  "recipient_delivery_verified": False, "helper_unload_policy": sending.POLICY}
        sending._persist(path, record)
        try:
            result, _ = sending._dispatch(prepared, 2)
            record["native"] = result
            record["native_submission_entered"] = result.get("native_send_entered")
            if not result.get("native_send_entered") and result.get("state") == 2:
                record.update(status="rejected_before_submission", message_send_performed=False)
            if result.get("send_returned"):
                record["local_message_id"] = result["ids"][2]
            sending._persist(path, record)
            if record.get("local_message_id"):
                for _ in range(30):
                    record = sending._reconcile(record)
                    if record["ok"]:
                        break
                    time.sleep(0.5)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            record["error"] = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        record["completed_at"] = time.time()
        sending._persist(path, record)
        return record


def forward(name, chat, message_id, recipient, request_id):
    kind, raw, source = _source(name, chat, message_id)
    return _send(name, recipient, kind, raw, request_id, "forward", source)


def send_xml(name, chat, source, request_id):
    data, metadata = assets.snapshot_bytes(source, "XML")
    kind, raw = parse_xml(data)
    return _send(name, chat, kind, raw, request_id, "xml", {"xml_sha256": metadata["sha256"]})


def xml_preflight(name, chat, source):
    data, _ = assets.snapshot_bytes(source, "XML")
    kind, raw = parse_xml(data)
    with sending._lock():
        return _check(_prepare(name, chat, kind, raw))
