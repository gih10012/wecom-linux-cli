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


def main() -> int:
    parser = argparse.ArgumentParser(prog="wecom-linux")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Inspect configured client; does not start it")
    client = sub.add_parser("client", help="Manage the explicitly configured isolated client")
    clientsub = client.add_subparsers(dest="client_command", required=True)
    clientsub.add_parser("start", help="Start client in existing desktop session; no autostart")
    keys = sub.add_parser("keys", help="Read-only capture and verification of a local cipher key")
    keysub = keys.add_subparsers(dest="key_command", required=True)
    keycapture = keysub.add_parser("capture")
    keycapture.add_argument("--database", type=Path, required=True)
    db = sub.add_parser("db", help="Inspect a validated copied local database")
    dbsub = db.add_subparsers(dest="db_command", required=True)
    check = dbsub.add_parser("inspect")
    check.add_argument("--database", type=Path, required=True)
    check.add_argument("--key-file", type=Path, help="Owner-only JSON file containing raw_key_hex")
    args = parser.parse_args()
    try:
        if args.command == "status":
            result = status()
        elif args.command == "client":
            result = start()
        elif args.command == "keys":
            result = capture(args.database)
        else:
            result = inspect(args.database, args.key_file)
    except (OSError, ValueError, sqlite3.DatabaseError, subprocess.TimeoutExpired) as exc:
        result = {"ok": False, "code": str(exc) if isinstance(exc, ValueError) else type(exc).__name__}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result and result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
