"""Measure the configured Wine process group without starting a client."""

import os
import time
from pathlib import Path

from .client import config, processes


def sample(prefix: Path) -> dict[int, dict]:
    expected = b"WINEPREFIX=" + os.fsencode(str(prefix.resolve()))
    page = os.sysconf("SC_PAGE_SIZE")
    rows = {}
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            if path.stat().st_uid != os.getuid():
                continue
            if expected not in (path / "environ").read_bytes().split(b"\0"):
                continue
            command = (path / "cmdline").read_bytes().split(b"\0")[0].decode(errors="replace")
            name = command.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            if not (name.lower().endswith(".exe") or name in {
                "wine", "wine64", "wineserver", "wine-preloader", "wine64-preloader",
            }):
                continue
            fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
            row = {"pid": int(path.name), "name": name, "start_time": int(fields[19]),
                   "ticks": int(fields[11]) + int(fields[12]), "rss_bytes": int(fields[21]) * page,
                   "pss_bytes": None, "private_bytes": None}
            try:
                values = {}
                for line in (path / "smaps_rollup").read_text().splitlines():
                    key, sep, value = line.partition(":")
                    if sep and key in {"Pss", "Private_Clean", "Private_Dirty", "Private_Hugetlb"}:
                        values[key] = int(value.split()[0]) * 1024
                row["pss_bytes"] = values.get("Pss")
                if "Private_Clean" in values and "Private_Dirty" in values:
                    row["private_bytes"] = sum(values.get(k, 0) for k in (
                        "Private_Clean", "Private_Dirty", "Private_Hugetlb",
                    ))
            except OSError:
                pass
            # The process could exit/restart while files are read. Keep only
            # records whose creation time still matches the initial stat.
            after = (path / "stat").read_text().rsplit(")", 1)[1].split()
            if int(after[19]) == row["start_time"]:
                rows[row["pid"]] = row
        except (OSError, ValueError, IndexError):
            continue
    return rows


def measure(seconds: float = 5) -> dict:
    if not 1 <= seconds <= 60:
        raise ValueError("RESOURCE_DURATION_MUST_BE_1_TO_60_SECONDS")
    current = config()
    if not current.get("prefix") or not current.get("executable"):
        raise ValueError("CLIENT_NOT_CONFIGURED")
    prefix = Path(current["prefix"]).resolve()
    executable = Path(current["executable"]).resolve()
    client_before = processes(prefix, executable)
    if len(client_before) != 1:
        raise ValueError("ONE_RUNNING_CLIENT_REQUIRED")
    started = time.monotonic()
    before = sample(prefix)
    time.sleep(seconds)
    after = sample(prefix)
    elapsed = time.monotonic() - started
    client_unchanged = processes(prefix, executable) == client_before
    stable = {pid for pid in before.keys() & after.keys()
              if before[pid]["start_time"] == after[pid]["start_time"]}
    group_unchanged = stable == before.keys() == after.keys()
    ticks = sum(max(0, after[pid]["ticks"] - before[pid]["ticks"]) for pid in stable)
    pss_complete = bool(after) and all(row["pss_bytes"] is not None for row in after.values())
    private_complete = bool(after) and all(row["private_bytes"] is not None for row in after.values())
    return {
        "ok": True, "scope": "configured_wine_process_group", "elapsed_seconds": round(elapsed, 3),
        "client_identity_unchanged": client_unchanged, "process_group_unchanged": group_unchanged,
        "process_count": len(after), "stable_process_count": len(stable),
        "cpu_percent_one_core": round(ticks / os.sysconf("SC_CLK_TCK") / elapsed * 100, 3),
        "cpu_covers_only_stable_processes": True,
        "rss_sum_bytes": sum(row["rss_bytes"] for row in after.values()),
        "rss_includes_shared_pages": True,
        "pss_sum_bytes": sum(row["pss_bytes"] for row in after.values()) if pss_complete else None,
        "private_sum_bytes": sum(row["private_bytes"] for row in after.values()) if private_complete else None,
        "processes": [{key: value for key, value in row.items() if key != "ticks"} for row in after.values()],
        "login_verified": False, "message_send_performed": False, "autostart_changed": False,
    }
