"""Unit coverage for the new-system installation readiness check."""

from __future__ import annotations

from pathlib import Path

from scytaledroid.Diagnostics import deployment_check
from scytaledroid.Diagnostics import installation_check as check


def _seed_source(root: Path) -> None:
    (root / "scytaledroid").mkdir()
    for name in check.REQUIRED_SOURCE_PATHS:
        path = root / name
        if name != "scytaledroid":
            path.write_text("present\n", encoding="utf-8")


def test_installation_state_requires_env_before_setup_marker(tmp_path: Path) -> None:
    _seed_source(tmp_path)

    state = check.describe_installation_state(tmp_path)

    assert state.level == "setup-required"
    assert ".env.example" in state.detail


def test_database_preflight_reports_unconfigured_dsn_without_loading_driver(monkeypatch) -> None:
    monkeypatch.delenv("SCYTALEDROID_DB_URL", raising=False)
    monkeypatch.delenv("SCYTALEDROID_DB_NAME", raising=False)

    checks = deployment_check._database_check(require_database=False)  # noqa: SLF001 - launcher contract

    assert checks == [
        deployment_check.CheckLine("warn", "database", "DSN unset (.env / SCYTALEDROID_DB_*)")
    ]


def test_collect_checks_reports_fresh_clone_without_hard_workspace_failure(monkeypatch, tmp_path: Path) -> None:
    _seed_source(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("SCYTALEDROID_DB_NAME=test\n", encoding="utf-8")
    env_file.chmod(0o600)
    monkeypatch.setattr(
        check,
        "_database_check",
        lambda require_database: [check.CheckLine("warn", "database", "DSN unset")],
    )
    monkeypatch.setattr(check, "_permission_intel_check", lambda: check.CheckLine("warn", "permission intel", "unset"))

    checks = check.collect_checks(
        repo_root=tmp_path,
        require_database=False,
        tool_resolver=lambda _tool: None,
    )

    by_topic = {line.topic: line for line in checks}
    assert by_topic["configuration"].level == "ok"
    assert by_topic["workspace"].level == "warn"
    assert by_topic["setup"].level == "warn"
    assert by_topic["adb"].level == "warn"


def test_collect_checks_accepts_restored_workspace_and_setup_marker(monkeypatch, tmp_path: Path) -> None:
    _seed_source(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("SCYTALEDROID_DB_NAME=test\n", encoding="utf-8")
    env_file.chmod(0o600)
    (tmp_path / ".setup").mkdir()
    (tmp_path / ".setup" / "requirements.sha256").write_text("hash\n", encoding="utf-8")
    venv_python = tmp_path / ".venv" / "bin" / "python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("placeholder\n", encoding="utf-8")
    for root in check._workspace_paths(tmp_path).values():  # noqa: SLF001 - seed each restore surface
        root.mkdir(parents=True)
        (root / ".restored").write_text("present\n", encoding="utf-8")
    (tmp_path / "data" / "store" / "apk" / "sha256").mkdir()
    monkeypatch.setattr(
        check,
        "_database_check",
        lambda require_database: [check.CheckLine("ok", "database", "reachable")],
    )
    monkeypatch.setattr(check, "_python_check", lambda: check.CheckLine("ok", "python", "3.13.0"))
    monkeypatch.setattr(check, "_permission_intel_check", lambda: check.CheckLine("ok", "permission intel", "ready"))

    checks = check.collect_checks(
        repo_root=tmp_path,
        require_database=True,
        tool_resolver=lambda _tool: "/usr/bin/tool",
    )

    assert all(line.level == "ok" for line in checks)
    assert check.describe_installation_state(tmp_path).level == "ready"


def test_environment_check_rejects_group_or_world_readable_env(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("SCYTALEDROID_DB_NAME=test\n", encoding="utf-8")
    env_file.chmod(0o640)

    result = check._environment_check(tmp_path)  # noqa: SLF001 - deployment contract

    assert result.level == "fail"
    assert "permissions 640" in result.message


def test_environment_check_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "secret.env"
    target.write_text("SCYTALEDROID_DB_NAME=test\n", encoding="utf-8")
    target.chmod(0o600)
    (tmp_path / ".env").symlink_to(target)

    result = check._environment_check(tmp_path)  # noqa: SLF001 - deployment contract

    assert result.level == "fail"
    assert "not a symlink" in result.message


def test_collect_checks_reports_unvalidated_python_version(monkeypatch, tmp_path: Path) -> None:
    _seed_source(tmp_path)
    (tmp_path / ".env").write_text("SCYTALEDROID_DB_NAME=test\n", encoding="utf-8")
    monkeypatch.setattr(check, "_python_check", lambda: check.CheckLine("warn", "python", "3.14.0"))
    monkeypatch.setattr(
        check,
        "_database_check",
        lambda require_database: [check.CheckLine("ok", "database", "reachable")],
    )
    monkeypatch.setattr(check, "_permission_intel_check", lambda: check.CheckLine("ok", "permission intel", "ready"))

    checks = check.collect_checks(repo_root=tmp_path, require_database=True, tool_resolver=lambda _tool: "/bin/tool")

    assert {line.topic: line for line in checks}["python"].level == "warn"


def test_cold_apk_store_check_fails_for_broken_canonical_symlink(tmp_path: Path) -> None:
    apk = tmp_path / "data" / "store" / "apk" / "sha256" / "aa" / ("a" * 64 + ".apk")
    apk.parent.mkdir(parents=True)
    apk.symlink_to(tmp_path / "missing.apk")

    result = check._cold_apk_store_check(tmp_path)  # noqa: SLF001 - targeted check contract

    assert result.level == "fail"
    assert "cold storage" in result.message


def test_dynamic_alias_check_reports_orphaned_legacy_alias(tmp_path: Path) -> None:
    canonical = tmp_path / "data" / "evidence" / "dynamic"
    legacy = tmp_path / "output" / "evidence" / "dynamic"
    canonical.mkdir(parents=True)
    legacy.mkdir(parents=True)
    (legacy / "orphan").symlink_to(tmp_path / "old-host" / "orphan", target_is_directory=True)

    result = check._dynamic_alias_check(tmp_path)  # noqa: SLF001 - targeted check contract

    assert result.level == "warn"
    assert "orphaned=1" in result.message
