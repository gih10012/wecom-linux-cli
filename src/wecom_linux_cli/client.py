"""Inspect or launch the owner's explicitly configured Wine client."""

import os
import re
import shutil
import subprocess
from pathlib import Path

from .state import private_root, read_private

DESKTOP_VARIABLES = {
    "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
    "XDG_SESSION_TYPE", "XAUTHORITY",
}
CLIENT_VARIABLES = {
    "WINEDLLOVERRIDES", "LIBGL_ALWAYS_SOFTWARE", "QT_OPENGL", "WINEDEBUG", "LANG", "LC_ALL",
}


def config() -> dict:
    path = private_root() / "client.json"
    return read_private(path) if path.is_file() else {}


def processes(prefix: Path, executable: Path | None = None) -> list[dict]:
    found = []
    expected = b"WINEPREFIX=" + os.fsencode(str(prefix.resolve()))
    paths = None
    if executable is not None:
        executable = executable.resolve()
        relative = executable.relative_to(prefix.resolve() / "drive_c")
        paths = {os.fsencode(str(executable)).lower(),
                 os.fsencode("C:\\" + str(relative).replace("/", "\\")).lower()}
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            if path.stat().st_uid != os.getuid():
                continue
            cmd = (path / "cmdline").read_bytes().split(b"\0")
            env = (path / "environ").read_bytes().split(b"\0")
            if expected not in env or not cmd or b"wxwork.exe" not in cmd[0].lower():
                continue
            # The logged-in client starts broker and rendering processes with
            # the same executable. They are not separate interactive clients.
            if b"--broker" in cmd or b"--from-broker" in cmd:
                continue
            if paths is not None and cmd[0].lower() not in paths:
                continue
            stat = (path / "stat").read_text().rsplit(")", 1)[1].split()
            found.append({"pid": int(path.name), "start_time": int(stat[19])})
        except (OSError, ValueError, IndexError):
            continue
    return found


def status() -> dict:
    wine = shutil.which("wine")
    version = None
    if wine:
        r = subprocess.run([wine, "--version"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            version = r.stdout.strip()
    current = config()
    prefix = Path(current["prefix"]) if current.get("prefix") else None
    executable = Path(current["executable"]) if current.get("executable") else None
    return {
        "ok": True,
        "wine_version": version,
        "configured": bool(prefix and executable),
        "client_version": current.get("version"),
        "client_installed": bool(executable and executable.is_file()),
        "processes": processes(prefix, executable) if prefix and executable and prefix.is_dir() else [],
        "message_read_available": (private_root() / "accounts/me.json").is_file(),
        "message_read_verification": "run conversations or messages for a validated snapshot",
        "message_send_verified": False,
        "autostart_policy": "not_installed_by_this_cli",
    }


def start() -> dict:
    current = config()
    if not current.get("prefix") or not current.get("executable"):
        raise ValueError("CLIENT_NOT_CONFIGURED")
    prefix = Path(current["prefix"]).resolve()
    executable = Path(current["executable"]).resolve()
    if not executable.is_relative_to(prefix / "drive_c") or not executable.is_file():
        raise ValueError("CLIENT_EXECUTABLE_OUTSIDE_PREFIX_OR_MISSING")
    if prefix.stat().st_uid != os.getuid() or prefix.stat().st_mode & 0o077:
        raise ValueError("UNSAFE_WINE_PREFIX")
    active = processes(prefix, executable)
    if active:
        return {"ok": True, "status": "already_running", "processes": active, "login_verified": False}
    wine = shutil.which("wine")
    if not wine:
        raise ValueError("WINE_NOT_INSTALLED")
    env = environment(current)
    if not env.get("DISPLAY") and not env.get("WAYLAND_DISPLAY"):
        raise ValueError("DESKTOP_SESSION_UNAVAILABLE")
    args = [wine]
    desktop = current.get("desktop")
    if desktop:
        if not isinstance(desktop, str) or not re.fullmatch(r"[A-Za-z0-9_-]+,[1-9][0-9]{2,3}x[1-9][0-9]{2,3}", desktop):
            raise ValueError("INVALID_DESKTOP_CONFIGURATION")
        args += ["explorer", "/desktop=" + desktop]
    # Give Explorer a Windows path so client self-relaunches do not inherit
    # a Unix path that Windows path APIs cannot resolve.
    args.append("C:\\" + str(executable.relative_to(prefix / "drive_c")).replace("/", "\\"))
    path = private_root() / "client-launch.log"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        child = subprocess.Popen(args, env=env, stdout=fd, stderr=fd, start_new_session=True)
    finally:
        os.close(fd)
    return {"ok": True, "status": "launch_requested", "launcher_pid": child.pid,
            "login_verified": False, "message_send_performed": False}


def environment(current: dict) -> dict:
    """Recover display variables for the owner's already existing session."""
    env = os.environ.copy()
    runtime = f"/run/user/{os.getuid()}"
    env.setdefault("XDG_RUNTIME_DIR", runtime)
    env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime}/bus")
    # Remote shells often lack the current desktop's variables. Read only
    # display variables from the owner's existing user manager environment.
    result = subprocess.run(
        ["systemctl", "--user", "show-environment"], env=env,
        capture_output=True, text=True, timeout=5,
    )
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            name, sep, value = line.partition("=")
            if sep and name in DESKTOP_VARIABLES and not env.get(name):
                env[name] = value
    for name, value in current.get("environment", {}).items():
        if name in CLIENT_VARIABLES and isinstance(value, str):
            env[name] = value
    env["WINEPREFIX"] = str(Path(current["prefix"]).resolve())
    return env
