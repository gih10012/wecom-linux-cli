"""JSON command-line entry point. Report only implemented capabilities."""

import argparse
import json
import sys
import sqlite3
import subprocess
from pathlib import Path

from . import __version__
from .client import status, start
from .database import inspect
from .keys import capture
from .resources import measure
from .messages import configure, conversations, messages
from .sending import preflight, send_text, send_status
from .sending_images import preflight as image_preflight, send_image
from .sending_files import preflight as file_preflight, send_file
from .sending_stickers import preflight as sticker_preflight, send_sticker
from .sending_cards import forward, message_xml, send_xml, xml_preflight
from .media import export as export_media


def main() -> int:
    parser = argparse.ArgumentParser(prog="wecom-linux")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Inspect configured client; does not start it")
    client = sub.add_parser("client", help="Manage the explicitly configured isolated client")
    clientsub = client.add_subparsers(dest="client_command", required=True)
    clientsub.add_parser("start", help="Start client in existing desktop session; no autostart")
    resources = clientsub.add_parser("resources", help="Measure existing Wine processes; never starts client")
    resources.add_argument("--seconds", type=float, default=5)
    keys = sub.add_parser("keys", help="Read-only capture and verification of a local cipher key")
    keysub = keys.add_subparsers(dest="key_command", required=True)
    keycapture = keysub.add_parser("capture")
    keycapture.add_argument("--database", type=Path, required=True)
    db = sub.add_parser("db", help="Inspect a validated copied local database")
    dbsub = db.add_subparsers(dest="db_command", required=True)
    check = dbsub.add_parser("inspect")
    check.add_argument("--database", type=Path, required=True)
    check.add_argument("--key-file", type=Path, help="Owner-only JSON file containing raw_key_hex")
    accounts = sub.add_parser("account", help="Configure exact verified owner database paths")
    accountsub = accounts.add_subparsers(dest="account_command", required=True)
    add = accountsub.add_parser("configure")
    add.add_argument("--account", default="me")
    add.add_argument("--data-dir", type=Path, required=True)
    add.add_argument("--key-file", type=Path, required=True)
    for command in ("send-text", "send-preflight"):
        send = sub.add_parser(command, help="Native owner identity text; caller checks recipient authorization")
        send.add_argument("--account", default="me")
        send.add_argument("--chat", required=True)
        send.add_argument("--text", required=True)
        if command == "send-text":
            send.add_argument("--request-id", required=True)
    send_query = sub.add_parser("send-status", help="Read/reconcile an existing request; never sends")
    send_query.add_argument("--request-id", required=True)
    for command in ("forward", "message-xml"):
        card = sub.add_parser(command, help="Read/forward an exact locally synced article or mini-program")
        card.add_argument("--account", default="me")
        card.add_argument("--chat", required=True)
        card.add_argument("--message-id", type=int, required=True)
        if command == "forward":
            card.add_argument("--recipient", required=True)
            card.add_argument("--request-id", required=True)
    for command in ("send-xml", "send-xml-preflight"):
        card = sub.add_parser(command, help="Native card XML; caller checks recipient authorization")
        card.add_argument("--account", default="me")
        card.add_argument("--chat", required=True)
        card.add_argument("--xml", type=Path, required=True)
        if command == "send-xml":
            card.add_argument("--request-id", required=True)
    for command in ("send-image", "send-image-preflight", "send-file", "send-file-preflight", "send-sticker", "send-sticker-preflight"):
        media = command.split("-")[1]
        send = sub.add_parser(command, help=f"Native {media}; caller checks recipient authorization")
        send.add_argument("--account", default="me")
        send.add_argument("--chat", required=True)
        send.add_argument(f"--{media}", type=Path, required=True)
        if not command.endswith("preflight"):
            send.add_argument("--request-id", required=True)
    media = sub.add_parser("media", help="Export hash-verified full media from the client cache")
    media_sub = media.add_subparsers(dest="media_command", required=True)
    media_export = media_sub.add_parser("export", help="Export cached original PNG/JPEG images")
    media_export.add_argument("--account", default="me")
    media_export.add_argument("--chat", required=True)
    media_export.add_argument("--message-id", type=int, required=True)
    for command in ("conversations", "messages"):
        read = sub.add_parser(command, help="Read locally synced owner history")
        read.add_argument("--account", default="me")
        read.add_argument("--limit", type=int, default=20)
        read.add_argument("--cursor")
        read.add_argument("--all", action="store_true", dest="all_history")
        if command == "messages":
            read.add_argument("--chat", required=True)
        else:
            read.add_argument("--query", default="")
    args = parser.parse_args()
    try:
        if args.command == "status":
            result = status()
        elif args.command == "client":
            result = start() if args.client_command == "start" else measure(args.seconds)
        elif args.command == "keys":
            result = capture(args.database)
        elif args.command == "account":
            result = configure(args.account, args.data_dir, args.key_file)
        elif args.command == "conversations":
            result = conversations(args.account, args.query, args.limit, args.cursor, args.all_history)
        elif args.command == "messages":
            result = messages(args.account, args.chat, args.limit, args.cursor, args.all_history)
        elif args.command == "send-preflight":
            result = preflight(args.account, args.chat, args.text)
        elif args.command == "send-text":
            result = send_text(args.account, args.chat, args.text, args.request_id)
        elif args.command == "send-image-preflight":
            result = image_preflight(args.account, args.chat, args.image)
        elif args.command == "send-image":
            result = send_image(args.account, args.chat, args.image, args.request_id)
        elif args.command == "send-file-preflight":
            result = file_preflight(args.account, args.chat, args.file)
        elif args.command == "send-file":
            result = send_file(args.account, args.chat, args.file, args.request_id)
        elif args.command == "send-sticker-preflight":
            result = sticker_preflight(args.account, args.chat, args.sticker)
        elif args.command == "send-sticker":
            result = send_sticker(args.account, args.chat, args.sticker, args.request_id)
        elif args.command == "send-status":
            result = send_status(args.request_id)
        elif args.command == "message-xml":
            result = message_xml(args.account, args.chat, args.message_id)
        elif args.command == "forward":
            result = forward(args.account, args.chat, args.message_id, args.recipient, args.request_id)
        elif args.command == "send-xml":
            result = send_xml(args.account, args.chat, args.xml, args.request_id)
        elif args.command == "send-xml-preflight":
            result = xml_preflight(args.account, args.chat, args.xml)
        elif args.command == "media":
            result = export_media(args.account, args.chat, args.message_id)
        else:
            result = inspect(args.database, args.key_file)
    except (OSError, ValueError, sqlite3.DatabaseError, subprocess.TimeoutExpired) as exc:
        result = {"ok": False, "code": str(exc) if isinstance(exc, ValueError) else type(exc).__name__}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result and result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
