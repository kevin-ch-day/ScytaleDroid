from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.contract, pytest.mark.gate]

ROOT = Path(__file__).resolve().parents[2]

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]+")),
    ("github_classic_pat", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----")),
)

TEXT_SUFFIXES = {
    ".md",
    ".py",
    ".json",
    ".txt",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".env.example",
    ".sh",
}

APPROVED_SQL_ROOTS = {
    Path("scripts/db"),
    Path("scytaledroid/Database/db_scripts"),
}

BACKUP_TOKENS = {"backup", "backups", "dump", "dumps", "db_backups"}
DUMP_SUFFIXES = {".sql", ".sql.gz", ".sql.xz", ".dump", ".dmp", ".sqlite", ".sqlite3", ".db"}
RUNTIME_ARTIFACT_ROOTS = {
    Path("data"),
    Path("logs"),
    Path("output"),
    Path("evidence"),
}
ALLOWED_TRACKED_ENV_FILES = {
    Path(".env.example"),
}


def _tracked_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=False,
    )
    return [
        Path(raw.decode("utf-8"))
        for raw in proc.stdout.split(b"\x00")
        if raw
    ]


def _looks_like_dump_artifact(path: Path) -> bool:
    suffix_joined = "".join(path.suffixes[-2:]) if len(path.suffixes) >= 2 else path.suffix
    if suffix_joined not in DUMP_SUFFIXES and path.suffix not in DUMP_SUFFIXES:
        return False
    if any(root == path or root in path.parents for root in APPROVED_SQL_ROOTS):
        return False
    lowered_parts = {part.lower() for part in path.parts}
    stem = path.stem.lower()
    return bool(lowered_parts & BACKUP_TOKENS) or any(token in stem for token in BACKUP_TOKENS)


def _should_scan_text(path: Path) -> bool:
    if path.name == ".env.example":
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def _is_runtime_artifact_path(path: Path) -> bool:
    return any(root == path or root in path.parents for root in RUNTIME_ARTIFACT_ROOTS)


def _is_tracked_env_file(path: Path) -> bool:
    name = path.name
    return name == ".env" or name.startswith(".env.")


def test_repo_has_no_tracked_backup_or_dump_artifacts_outside_approved_sql_roots() -> None:
    offenders = sorted(str(path) for path in _tracked_files() if _looks_like_dump_artifact(path))
    assert offenders == [], (
        "tracked backup/dump artifacts should not live in the repo; "
        "keep operational dumps outside the worktree or under ignored local paths: "
        + ", ".join(offenders)
    )


def test_repo_has_no_tracked_runtime_artifact_roots() -> None:
    offenders = sorted(str(path) for path in _tracked_files() if _is_runtime_artifact_path(path))
    assert offenders == [], (
        "runtime artifacts should not be tracked; keep live data under ignored local paths: "
        + ", ".join(offenders)
    )


def test_repo_only_tracks_approved_env_example_files() -> None:
    offenders = sorted(
        str(path)
        for path in _tracked_files()
        if _is_tracked_env_file(path) and path not in ALLOWED_TRACKED_ENV_FILES
    )
    assert offenders == [], (
        "tracked env files should be limited to documented examples; move live env files out of Git: "
        + ", ".join(offenders)
    )


def test_tracked_text_sources_do_not_contain_live_secret_literals() -> None:
    hits: list[str] = []
    for rel_path in _tracked_files():
        if not _should_scan_text(rel_path):
            continue
        abs_path = ROOT / rel_path
        try:
            text = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                hits.append(f"{rel_path}: {label}")
    assert hits == [], (
        "tracked text sources contain secret-like literals; use redacted or runtime-built fixtures instead:\n"
        + "\n".join(sorted(hits))
    )
