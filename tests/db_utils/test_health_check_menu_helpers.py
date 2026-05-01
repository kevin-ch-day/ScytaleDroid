from scytaledroid.Database.db_utils.menus.health_checks_inventory import run_inventory_health_check
from scytaledroid.Database.db_utils.menus import health_checks
from scytaledroid.Database.db_utils.menus.health_checks_permission import render_scoring_checks
from scytaledroid.Database.db_utils.menus.health_checks_static import render_integrity_checks


class _MenuUtils:
    def __init__(self):
        self.sections = []

    def print_section(self, title):
        self.sections.append(title)


class _StatusMessages:
    @staticmethod
    def status(message, level="info"):
        return f"[{level}] {message}"


def test_render_scoring_checks_handles_no_snapshots_and_optional_tables():
    calls = []

    def print_status_line(level, label, *, detail=None):
        calls.append((level, label, detail))

    def run_sql(sql, params=None, fetch=None, dictionary=False):
        if "SELECT s.snapshot_id" in sql:
            return []
        if "SELECT grade, COUNT(*) AS cnt" in sql:
            return []
        return []

    def scalar(sql, params=None):
        if "COUNT(*)\n        FROM (" in sql:
            return 0
        if "SELECT COUNT(*)\n        FROM static_analysis_runs sar" in sql:
            return 0
        if "SELECT MAX(snapshot_id)" in sql:
            return None
        if "SELECT COUNT(*) FROM contributors" in sql:
            return 0
        if "SELECT COUNT(*) FROM risk_scores" in sql:
            return 0
        if "SELECT COUNT(*) FROM static_permission_risk_vnext" in sql:
            return 0
        return 0

    render_scoring_checks(
        run_sql=run_sql,
        scalar=scalar,
        print_status_line=print_status_line,
        status_messages=_StatusMessages(),
    )

    assert ("warn", "permission audit", "no snapshots recorded yet") in calls
    assert ("warn", "grade distribution", "no snapshots available") in calls
    assert any(label == "risk_scores" and level == "info" for level, label, _ in calls)


def test_run_inventory_health_check_passes_computed_snapshot_inputs():
    menu_utils = _MenuUtils()
    forwarded = {}

    def scalar(sql, params=None):
        if "device_inventory_snapshots" in sql and "LEFT JOIN" not in sql:
            return 3
        if "LEFT JOIN device_inventory" in sql:
            return 1
        if "device_inventory WHERE snapshot_id" in sql:
            return 8
        return 0

    def run_sql(sql, params=None, fetch=None, dictionary=False):
        return (42, 10)

    def print_status_line(level, label, *, detail=None):
        pass

    def run_inventory_snapshot_checks(**kwargs):
        forwarded.update(kwargs)

    run_inventory_health_check(
        menu_utils=menu_utils,
        run_sql=run_sql,
        scalar=scalar,
        print_status_line=print_status_line,
        run_inventory_snapshot_checks=run_inventory_snapshot_checks,
    )

    assert menu_utils.sections == ["Inventory DB health"]
    assert forwarded["latest_snapshot_id"] == 42
    assert forwarded["latest_expected"] == 10
    assert forwarded["latest_rows"] == 8
    assert forwarded["latest_is_orphan"] is False


def test_render_integrity_checks_warns_when_no_summaries():
    calls = []

    def print_status_line(level, label, *, detail=None):
        calls.append((level, label, detail))

    def run_sql(sql, params=None, fetch=None, dictionary=False):
        return []

    render_integrity_checks(
        run_sql=run_sql,
        print_status_line=print_status_line,
        session_stamp=None,
    )

    assert calls[0] == ("warn", "latest APK ↔ summary", "view checks disabled by policy (no DB views)")
    assert ("warn", "summary ↔ string samples", "no summaries found for recent sessions") in calls


def test_health_checks_scoring_delegate_wires_dependencies(monkeypatch):
    captured = {}

    def fake_render_scoring_checks(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(health_checks, "render_scoring_checks", fake_render_scoring_checks)

    health_checks._render_scoring_checks()

    assert captured["run_sql"] is health_checks.run_sql
    assert captured["scalar"] is health_checks.scalar
    assert captured["print_status_line"] is health_checks._print_status_line
    assert captured["status_messages"] is health_checks.status_messages


def test_health_checks_integrity_delegate_wires_dependencies(monkeypatch):
    captured = {}

    def fake_render_integrity_checks(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(health_checks, "render_integrity_checks", fake_render_integrity_checks)

    health_checks._render_integrity_checks("sess-123")

    assert captured["run_sql"] is health_checks.run_sql
    assert captured["print_status_line"] is health_checks._print_status_line
    assert captured["session_stamp"] == "sess-123"


def test_health_checks_inventory_delegate_wires_dependencies(monkeypatch):
    captured = {}

    def fake_run_inventory_health_check(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(health_checks, "run_inventory_health_check", fake_run_inventory_health_check)

    health_checks._run_inventory_health_check()

    assert captured["menu_utils"] is health_checks.menu_utils
    assert captured["run_sql"] is health_checks.run_sql
    assert captured["scalar"] is health_checks.scalar
    assert captured["print_status_line"] is health_checks._print_status_line
    assert captured["run_inventory_snapshot_checks"] is health_checks.run_inventory_snapshot_checks
