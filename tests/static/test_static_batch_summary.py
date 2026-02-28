from pathlib import Path


def test_write_batch_summary_accepts_started_at_utc(tmp_path: Path):
    from scytaledroid.StaticAnalysis.cli.flows.static_batch import _write_batch_summary

    out = tmp_path / "nested" / "batch.json"
    rows = [
        {
            "package_name": "com.example",
            "display_name": "Example",
            "started_at_utc": "2026-02-28T00:00:00Z",
            "completed": True,
        }
    ]
    _write_batch_summary(
        batch_summary_path=out,
        batch_id="batch-1",
        batch_rows=rows,
        apps_total=1,
        apps_completed=1,
        apps_failed=0,
        ended_at="2026-02-28T00:01:00Z",
    )
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert "started_at_utc" in text
    assert "2026-02-28T00:00:00Z" in text


def test_write_batch_summary_accepts_started_at(tmp_path: Path):
    from scytaledroid.StaticAnalysis.cli.flows.static_batch import _write_batch_summary

    out = tmp_path / "batch.json"
    rows = [{"started_at": "2026-02-28T00:00:00Z"}]
    _write_batch_summary(
        batch_summary_path=out,
        batch_id="batch-2",
        batch_rows=rows,
        apps_total=1,
        apps_completed=1,
        apps_failed=0,
        ended_at=None,
    )
    assert out.exists()
