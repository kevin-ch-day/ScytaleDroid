from scytaledroid.StaticAnalysis.cli.persistence import run_envelope


class DummyManifest:
    def __init__(self):
        self.package_name = "com.example.app"
        self.app_label = "Example App"
        self.version_code = 1
        self.version_name = "1.0"
        self.target_sdk = 33


class DummyReport:
    def __init__(self):
        self.manifest = DummyManifest()
        self.metadata = {"session_stamp": "20240101-010101"}


def _build_baseline():
    return {"app": {"label": "Example App"}}


def test_prepare_run_envelope_reports_connection_failure(monkeypatch):
    report = DummyReport()

    def fake_create_run(**kwargs):
        raise RuntimeError("OperationalError: (2003, 'Can't connect to MySQL server')")

    def fake_run_sql(query, params=None, fetch=None, **kwargs):
        raise RuntimeError("OperationalError: (2003, 'Can't connect to MySQL server')")

    monkeypatch.setattr(run_envelope._dw, "create_run", fake_create_run)
    monkeypatch.setattr(run_envelope.core_q, "run_sql", fake_run_sql)

    envelope, errors = run_envelope.prepare_run_envelope(
        report=report,
        baseline_payload=_build_baseline(),
        run_package="com.example.app",
        session_stamp="20240101-010101",
        dry_run=False,
    )

    assert envelope.run_id is None
    assert any("OperationalError" in err for err in errors)
    assert any("Database connectivity check failed" in err for err in errors)


def test_prepare_run_envelope_reports_sql_issue_when_ping_succeeds(monkeypatch):
    report = DummyReport()

    def fake_create_run(**kwargs):
        raise RuntimeError("IntegrityError: duplicate entry '20240101' for key 'session'")

    def fake_run_sql(query, params=None, fetch=None, **kwargs):
        if str(query).strip().upper().startswith("SELECT 1"):
            return (1,)
        raise AssertionError("Unexpected query")

    monkeypatch.setattr(run_envelope._dw, "create_run", fake_create_run)
    monkeypatch.setattr(run_envelope.core_q, "run_sql", fake_run_sql)

    envelope, errors = run_envelope.prepare_run_envelope(
        report=report,
        baseline_payload=_build_baseline(),
        run_package="com.example.app",
        session_stamp="20240101-010101",
        dry_run=False,
    )

    assert envelope.run_id is None
    assert any("IntegrityError" in err for err in errors)
    assert any("SQL constraints" in err for err in errors)
