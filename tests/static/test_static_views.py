from scytaledroid.StaticAnalysis.cli.views import render_run_start, render_run_summary


def test_render_run_start(capsys):
    render_run_start(
        run_id="RUN-123",
        profile_label="full_forensic",
        target='App "Example" (com.example.app)',
        modules=("permissions", "strings"),
        workers_desc="auto (8)",
        cache_desc="purge",
        log_level="info",
        perm_cache_desc="refresh",
        trace_ids=("det1",),
    )
    out = capsys.readouterr().out
    assert "Static Analysis · Configuration" in out
    assert "Target" in out
    assert "permissions, strings" in out
    assert "Workers" in out


def test_render_run_summary(capsys):
    render_run_summary(
        run_id="RUN-123",
        profile_label="full_forensic",
        target="Example (com.example.app)",
        detectors_count=2,
        findings_total=5,
        sev_counts={"high": 1, "medium": 2, "low": 2},
        failed_masvs=("MSTG-PLATFORM-1",),
        perm_stats={"dangerous": 3, "signature": 1, "custom": 0},
        evidence_root="/tmp/evidence",
    )
    out = capsys.readouterr().out
    assert "Static Analysis · Complete" in out
    assert "Total findings" in out
    assert "MASVS coverage" in out
    assert "/tmp/evidence" in out
