"""Private state and bounded reads from owner-selected local files."""

import json
import os
import tempfile
from pathlib import Path


def private_root() -> Path:
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
    path = base / "wecom-linux-cli"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.getuid():
        raise ValueError("UNSAFE_STATE_DIRECTORY")
    path.chmod(0o700)
    return path


def write_private(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def read_private(path: Path) -> dict:
    with path.open("rb") as stream:
        s = os.fstat(stream.fileno())
        if s.st_uid != os.getuid() or s.st_mode & 0o077:
            raise ValueError("UNSAFE_PRIVATE_FILE_PERMISSIONS")
        return json.load(stream)
