from scytaledroid.Utils.DisplayUtils import terminal


def test_use_ascii_ui_force_refresh(monkeypatch):
    baseline = terminal.use_ascii_ui(force_refresh=True)
    monkeypatch.setenv("ASCII_UI", "1")
    try:
        assert terminal.use_ascii_ui(force_refresh=True) is True
    finally:
        monkeypatch.delenv("ASCII_UI", raising=False)
    assert terminal.use_ascii_ui(force_refresh=True) == baseline
