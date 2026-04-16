from scytaledroid.StaticAnalysis.cli.views import render_run_start


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
    assert "Static Analysis · Settings" in out
    assert "App" in out
    assert "permissions, strings" in out
    assert "Workers" in out
