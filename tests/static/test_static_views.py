from scytaledroid.StaticAnalysis.cli.views import render_run_start


def test_render_run_start(capsys):
    render_run_start(
        profile_label="full_forensic",
        target='App "Example" (com.example.app)',
        modules=("permissions", "strings"),
        workers_desc="auto (8)",
    )
    out = capsys.readouterr().out
    assert "Static Analysis" in out
    assert "full_forensic | workers=auto (8) | profile_modules=2" in out
    assert 'Target: App "Example" (com.example.app)' in out
