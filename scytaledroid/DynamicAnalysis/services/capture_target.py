"""Read-only installed-byte verification for the capture-first entry point."""

from __future__ import annotations

import json
import re
import shlex
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scytaledroid.Utils.install_set_identity import compute_artifact_set_hash


class TargetUnavailable(ValueError):
    """An exact installed build cannot be established safely."""


@dataclass(frozen=True)
class InstalledBuild:
    package: str
    version_code: str
    version_name: str
    members: tuple[tuple[str, str], ...]

    @property
    def base_sha256(self) -> str:
        if len(self.members) == 1:
            return self.members[0][1]
        bases = [digest for path, digest in self.members if Path(path).name == "base.apk"]
        if len(bases) != 1:
            raise TargetUnavailable("Installed APK paths do not identify exactly one base.apk.")
        return bases[0]


def read_installed_build(serial: str, package: str) -> InstalledBuild:
    from scytaledroid.DeviceAnalysis.adb import package_manager as pm
    from scytaledroid.DeviceAnalysis.adb.shell import run_shell, run_shell_command

    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package):
        raise TargetUnavailable("Select a recognized application package.")
    user = pm.configured_user_id()
    if user is not None and not user.isdecimal():
        raise TargetUnavailable("Configured Android user must be a numeric user ID.")

    def paths():
        # Explicit user scope: do not fall back to a different Android user.
        command = ["pm", "path", *(["--user", user] if user is not None else []), package]
        text = run_shell(serial, command, check=True)
        rows = [
            line.removeprefix("package:").strip()
            for line in text.splitlines()
            if line.startswith("package:")
        ]
        if not rows or len(set(rows)) != len(rows) or any(not p.startswith("/") for p in rows):
            raise TargetUnavailable(
                "No complete installed APK path list. Check device/user and install the app."
            )
        return sorted(rows)

    def version():
        result, _command = pm.read_supported_metadata_dump(
            serial,
            package,
            run_command=lambda command: run_shell_command(serial, command),
            is_successful=lambda result: result.returncode == 0,
            extract_text=lambda result: result.stdout,
            accept_text=lambda text: pm.output_looks_package_specific(text, package),
        )
        text = result.stdout if result else ""
        # Scope version fields to the selected Package section, not another package.
        section = re.search(r"(?m)^\s*Package \[" + re.escape(package) + r"\][^\n]*\n", text)
        if not section:
            raise TargetUnavailable("Installed package version metadata unavailable.")
        body = re.split(r"(?m)^\s*Package \[", text[section.end() :], maxsplit=1)[0]
        code = re.search(r"\bversionCode=(\d+)", body)
        name = re.search(r"(?m)^\s*versionName=(.*)$", body)
        if not code:
            raise TargetUnavailable("Installed versionCode unavailable.")
        return code.group(1), name.group(1).strip() if name else ""

    before, apk_paths = version(), paths()
    members = []
    for path in apk_paths:
        output = run_shell(serial, ["sha256sum", shlex.quote(path)], timeout=120, check=True)
        digest = output.split()[0] if output.split() else ""
        if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise TargetUnavailable(
                "Unable to read an installed APK hash; capture was not started."
            )
        members.append((path, digest.lower()))
    if before != version() or apk_paths != paths():
        raise TargetUnavailable(
            "Installed build changed during verification. Select the app again."
        )
    build = InstalledBuild(package, *before, tuple(members))
    _base_sha256 = build.base_sha256  # require unambiguous base identity
    return build


def members_match(build: InstalledBuild, selection: dict, members: list[dict]) -> bool:
    version = selection.get("artifact_set_hash_version")
    if version not in {"v1", "v2"} or not members:
        return False
    if str(selection.get("version_code")) != build.version_code:
        return False
    if selection.get("package_name") != build.package:
        return False
    if build.version_name and str(selection.get("version_name") or "") != build.version_name:
        return False
    bases = [m for m in members if m.get("role") == "base"]
    if len(bases) != 1 or bases[0].get("sha256") != build.base_sha256:
        return False
    if selection.get("base_apk_sha256") != build.base_sha256:
        return False
    if any(m.get("role") not in {"base", "split"} for m in members):
        return False
    if Counter(digest for _, digest in build.members) != Counter(m.get("sha256") for m in members):
        return False
    return compute_artifact_set_hash(members, version=version) == selection.get("artifact_set_hash")


def select_exact_plan(build: InstalledBuild) -> dict:
    from scytaledroid.Database.db_core import db_queries
    from scytaledroid.DynamicAnalysis.plan_selection import _build_selection, load_plan_candidates
    from scytaledroid.DynamicAnalysis.plans.validation import validate_dynamic_plan

    candidates, _note = load_plan_candidates(build.package)
    for candidate in sorted(
        candidates, key=lambda c: str(c.get("generated_at") or ""), reverse=True
    ):
        selection = _build_selection(candidate)
        if str(selection.get("version_code")) != build.version_code:
            continue
        members = db_queries.run_sql(
            """SELECT m.role, m.split_name, m.sha256 FROM apk_set_members m
               JOIN apk_sets s ON s.apk_set_id=m.apk_set_id
               WHERE s.package_name=%s AND s.version_code=%s
                 AND s.artifact_set_hash=%s AND s.artifact_set_hash_version=%s""",
            (
                build.package,
                build.version_code,
                selection.get("artifact_set_hash"),
                selection.get("artifact_set_hash_version"),
            ),
            fetch="all_dict",
        )
        if not members_match(build, selection, members or []):
            continue
        payload = json.loads(Path(selection["plan_path"]).read_text(encoding="utf-8"))
        outcome = validate_dynamic_plan(
            payload, package_name=build.package, static_run_id=selection["static_run_id"]
        )
        if outcome.status != "PASS":
            continue
        return selection
    raise TargetUnavailable(
        "Static evidence: unavailable for these installed APK bytes. Harvest this installed build and run Static Analysis, then return to Run an app."
    )


def verification_record(build: InstalledBuild, selection: dict) -> dict:
    return {
        "verified_at": datetime.now(UTC).isoformat(),
        "package": build.package,
        "version_code": build.version_code,
        "version_name": build.version_name,
        "base_apk_sha256": build.base_sha256,
        "artifact_set_hash": selection["artifact_set_hash"],
        "artifact_set_hash_version": selection["artifact_set_hash_version"],
        "installed_apks": [{"path": p, "sha256": h} for p, h in build.members],
    }
