"""Read exact owner-configured account databases; no remote or send calls."""

import base64
import hashlib
import json
from pathlib import Path

from .client import config
from .content import decode, json_value
from .database import open_snapshot
from .state import private_root, read_private, write_private

REQUIRED = {
    "message.db": ("message_table", {"message_id", "server_id", "sender_id", "conversation_id",
                                     "content_type", "send_time", "content"}),
    "session.db": ("conversation_table", {"id", "name", "last_message_time"}),
    "user.db": ("user_table", {"id", "name"}),
}


def account_file(name: str) -> Path:
    if not name or len(name) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in name):
        raise ValueError("INVALID_ACCOUNT_NAME")
    return private_root() / "accounts" / (name + ".json")


def configure(name: str, data_dir: Path, key_file: Path) -> dict:
    current = config()
    if not current.get("prefix"):
        raise ValueError("CLIENT_NOT_CONFIGURED")
    data_dir, key_file = data_dir.resolve(), key_file.resolve()
    drive = Path(current["prefix"]).resolve() / "drive_c"
    if not data_dir.is_relative_to(drive):
        raise ValueError("ACCOUNT_OUTSIDE_CONFIGURED_PREFIX")
    account_file(name)  # Validate before opening databases.
    snapshots = {}
    for database, (table, required) in REQUIRED.items():
        with open_snapshot(data_dir / database, key_file) as (conn, evidence):
            columns = {row[1] for row in conn.execute('PRAGMA table_info("' + table + '")')}
            if not required <= columns:
                raise ValueError("UNSUPPORTED_WINDOWS_MESSAGE_SCHEMA")
            snapshots[database] = evidence
    write_private(account_file(name), {"data_dir": str(data_dir), "key_file": str(key_file),
                                       "self_id": data_dir.parent.name,
                                       "self_id_source": "account_directory_name"})
    return {"ok": True, "account": name, "status": "account_databases_verified",
            "snapshots": snapshots, "remote_login_verified": False, "message_send_performed": False}


def account(name: str) -> dict:
    path = account_file(name)
    if not path.exists():
        raise ValueError("ACCOUNT_NOT_CONFIGURED")
    value = read_private(path)
    value["data_dir"] = Path(value["data_dir"])
    value["key_file"] = Path(value["key_file"])
    value["scope"] = hashlib.sha256(str(value["data_dir"].resolve()).encode()).hexdigest()
    return value


def names(value: dict) -> tuple[dict, dict, dict]:
    users, chats, evidence = {}, {}, {}
    for database in ("user.db", "session.db"):
        with open_snapshot(value["data_dir"] / database, value["key_file"]) as (conn, snapshot):
            evidence[database] = snapshot
            if database == "user.db":
                users = {str(uid): name for uid, name in conn.execute("SELECT id,name FROM user_table") if name}
            else:
                chats = {cid: name for cid, name in conn.execute("SELECT id,name FROM conversation_table")}
    for cid in chats:
        if not chats[cid] and cid.startswith("S:"):
            participants = cid[2:].split("_")
            others = [uid for uid in participants if uid != value["self_id"]]
            if others:
                chats[cid] = users.get(others[0], "")
            elif participants and all(uid == value["self_id"] for uid in participants):
                chats[cid] = "文件传输助手"
    return users, chats, evidence


def encode_cursor(value: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def cursor_value(token: str | None, scope: str, command: str, chat: str) -> dict | None:
    if token is None:
        return None
    if len(token) > 2048:
        raise ValueError("INVALID_CURSOR")
    try:
        value = json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4)))
        if (value.get("version"), value.get("scope"), value.get("command"), value.get("chat")) != (1, scope, command, chat):
            raise ValueError()
        if not isinstance(value["time"], int) or not isinstance(value["id"], (int, str)):
            raise ValueError()
        return value
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ValueError("INVALID_OR_WRONG_SCOPE_CURSOR") from exc


def limit_check(limit: int) -> None:
    if not 1 <= limit <= 1000:
        raise ValueError("LIMIT_MUST_BE_1_TO_1000")


def conversations(name: str = "me", query: str = "", limit: int = 20,
                  cursor: str | None = None, all_history: bool = False) -> dict:
    limit_check(limit)
    value = account(name)
    _, chats, snapshots = names(value)
    token = cursor_value(cursor, value["scope"], "conversations", query)
    with open_snapshot(value["data_dir"] / "message.db", value["key_file"]) as (conn, snapshot):
        snapshots["message.db"] = snapshot
        rows = conn.execute("SELECT conversation_id,COUNT(*),MAX(send_time) FROM message_table GROUP BY conversation_id").fetchall()
    counts = {cid: (count, timestamp) for cid, count, timestamp in rows}
    result = []
    for cid in chats.keys() | counts.keys():
        title = chats.get(cid) or cid
        if query and query.casefold() not in title.casefold() and query.casefold() not in cid.casefold():
            continue
        count, timestamp = counts.get(cid, (0, 0))
        if token and (timestamp, cid) >= (token["time"], token["id"]):
            continue
        result.append({"chat_id": cid, "name": title, "message_count": count,
                       "last_message_time": timestamp, "history_scope": "locally_synced"})
    result.sort(key=lambda row: (row["last_message_time"], row["chat_id"]), reverse=True)
    more = not all_history and len(result) > limit
    result = result if all_history else result[:limit]
    next_cursor = None
    if more:
        last = result[-1]
        next_cursor = encode_cursor({"version": 1, "scope": value["scope"], "command": "conversations",
                                     "chat": query, "time": last["last_message_time"], "id": last["chat_id"]})
    return {"ok": True, "account": name, "items": result, "next_cursor": next_cursor,
            "snapshots": snapshots, "snapshot_atomic": False, "history_scope": "locally_synced",
            "remote_history_complete": False, "message_send_performed": False}


def messages(name: str, chat: str, limit: int = 20, cursor: str | None = None,
             all_history: bool = False) -> dict:
    limit_check(limit)
    value = account(name)
    users, chats, snapshots = names(value)
    if chat not in chats:
        exact = [cid for cid, title in chats.items() if title == chat]
        if len(exact) > 1:
            raise ValueError("AMBIGUOUS_CHAT_NAME_USE_EXACT_ID")
        if exact:
            chat = exact[0]
    token = cursor_value(cursor, value["scope"], "messages", chat)
    with open_snapshot(value["data_dir"] / "message.db", value["key_file"]) as (conn, snapshot):
        snapshots["message.db"] = snapshot
        maximum = conn.execute("SELECT COALESCE(MAX(message_id),0) FROM message_table").fetchone()[0]
        if token:
            if not isinstance(token.get("max_id"), int) or not isinstance(token["id"], int):
                raise ValueError("INVALID_CURSOR")
            maximum = token["max_id"]
        sql = "SELECT * FROM message_table WHERE conversation_id=? AND message_id<=?"
        parameters = [chat, maximum]
        if token:
            sql += " AND (send_time < ? OR (send_time=? AND message_id<?))"
            parameters += [token["time"], token["time"], token["id"]]
        sql += " ORDER BY send_time DESC,message_id DESC"
        if not all_history:
            sql += " LIMIT ?"
            parameters.append(limit + 1)
        result_set = conn.execute(sql, parameters)
        columns = [col[0] for col in result_set.description]
        rows = result_set.fetchall()
    more = not all_history and len(rows) > limit
    rows = rows if all_history else rows[:limit]
    result = []
    for row in rows:
        stored = dict(zip(columns, row))
        result.append({"message_id": stored["message_id"], "server_id": str(stored["server_id"]),
                       "chat_id": stored["conversation_id"], "sender_id": str(stored["sender_id"]),
                       "sender_name": users.get(str(stored["sender_id"])), "send_time": stored["send_time"],
                       "content": decode(stored["content_type"], stored["content"]),
                       "stored_fields": {key: str(val) if key in ("server_id", "sender_id") else json_value(val)
                                         for key, val in stored.items()}})
    next_cursor = None
    if more:
        last = result[-1]
        next_cursor = encode_cursor({"version": 1, "scope": value["scope"], "command": "messages", "chat": chat,
                                     "time": last["send_time"], "id": last["message_id"], "max_id": maximum})
    return {"ok": True, "account": name, "chat_id": chat, "chat_name": chats.get(chat), "items": result,
            "next_cursor": next_cursor, "snapshots": snapshots, "snapshot_atomic": False,
            "history_scope": "locally_synced", "remote_history_complete": False, "message_send_performed": False}
