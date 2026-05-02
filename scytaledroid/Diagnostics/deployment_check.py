"""Host smoke: Python, Fedora-ish OS hint, adb, optional MariaDB. Use `./run.sh --deploy-check`."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CheckLine:
    level: str
    topic: str
    message: str


def _read_os_release() -> dict[str, str]:
    release = Path("/etc/os-release")
    if not release.exists():
        return {}
    data: dict[str, str] = {}
    try:
        for raw in release.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            v = v.strip().strip('"')
            data[k.strip()] = v
    except OSError:
        return {}
    return data


def _python_check() -> CheckLine | None:
    # Runtime is 3.13+ (see ``pyproject.toml`` / Ruff target); avoid dead branches for older Pythons.
    return CheckLine("ok", "python", sys.version.split()[0])


def _fedora_check() -> CheckLine:
    env = _read_os_release()
    oid = env.get("ID", "").strip().lower()
    like = env.get("ID_LIKE", "").lower().split()
    if oid == "fedora" or "fedora" in like:
        return CheckLine("ok", "os", env.get("NAME") or oid)
    pretty = env.get("PRETTY_NAME") or oid or "unknown"
    return CheckLine("warn", "os", f"not Fedora ({pretty})")


def _adb_check(timeout_s: float = 8.0) -> list[CheckLine]:
    adb = shutil.which("adb")
    if not adb:
        return [
            CheckLine("fail", "adb", "not in PATH (dnf install android-tools)"),
        ]
    try:
        cp = subprocess.run(
            [adb, "devices"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [CheckLine("warn", "adb", "`adb devices` failed")]

    if cp.returncode != 0:
        tail = (cp.stderr or cp.stdout or "").strip()[:160]
        return [CheckLine("warn", "adb", f"exit {cp.returncode}: {tail}")]

    lines = [ln.strip() for ln in (cp.stdout or "").splitlines() if ln.strip()]
    body = [ln for ln in lines if ln != "List of devices attached"]
    if not body:
        return [
            CheckLine("warn", "adb", "no devices (USB debug + authorize?)"),
        ]

    authorized = sum(1 for ln in body if re.search(r"\tdevice$", ln))
    unauthorized = sum(1 for ln in body if "\tunauthorized" in ln)
    offline = sum(1 for ln in body if "\toffline" in ln)

    if authorized:
        msg = f"{authorized} device(s) ok"
        if unauthorized or offline:
            msg += f" ({unauthorized} unauthorized, {offline} offline)"
        return [CheckLine("ok", "adb", msg)]

    parts = ["none authorized"]
    if unauthorized:
        parts.append(f"{unauthorized} unauthorized")
    if offline:
        parts.append(f"{offline} offline")
    return [CheckLine("warn", "adb", ", ".join(parts))]


def _database_check(require_database: bool) -> list[CheckLine]:
    from scytaledroid.Database.db_core import db_config
    from scytaledroid.Database.db_utils import schema_gate

    if not db_config.db_enabled():
        msg = "DSN unset (.env / SCYTALEDROID_DB_*)"
        if require_database:
            return [CheckLine("fail", "database", msg)]
        return [CheckLine("warn", "database", msg)]

    ok, headline, detail = schema_gate.check_base_schema()
    if ok:
        return [CheckLine("ok", "database", "reachable")]

    severity = "fail" if require_database else "warn"
    lines = [CheckLine(severity, "database", headline)]
    if (detail or "").strip():
        lines.append(CheckLine(severity, "database", detail.strip()))
    return lines


def collect_checks(*, require_database: bool) -> list[CheckLine]:
    lines: list[CheckLine] = []
    py_line = _python_check()
    if py_line:
        lines.append(py_line)
    lines.append(_fedora_check())
    if py_line and py_line.level == "fail":
        return lines
    lines.extend(_adb_check())
    lines.extend(_database_check(require_database))
    return lines


def run(*, json_mode: bool, require_database: bool) -> int:
    checks = collect_checks(require_database=require_database)
    counts: dict[str, int] = {}
    for ln in checks:
        counts[ln.level] = counts.get(ln.level, 0) + 1

    payload = {
        "deployment_check": True,
        "require_database": require_database,
        "summary": counts,
        "checks": [{"level": c.level, "topic": c.topic, "message": c.message} for c in checks],
    }

    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("Deploy check")
        if os.environ.get("SCYTALEDROID_NO_DOTENV") == "1":
            print("  (.env load off — export DSN manually)")
        for ln in checks:
            tag = {"ok": " OK", "warn": " !!", "fail": " XX"}.get(ln.level, " ?")
            print(f" {tag}  {ln.topic:10} {ln.message}")
        print(f"  → ok={counts.get('ok', 0)} warn={counts.get('warn', 0)} fail={counts.get('fail', 0)}")

    return 1 if counts.get("fail") else 0


__all__ = ["CheckLine", "collect_checks", "run"]
