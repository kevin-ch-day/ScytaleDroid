from __future__ import annotations

import main
import pytest


class _CaptureLogger:
    def __init__(self) -> None:
        self.messages: list[tuple[str, dict[str, object] | None]] = []

    def exception(self, message, *, extra=None):
        self.messages.append((str(message), dict(extra or {})))


def test_main_logs_unhandled_exception_before_reraising(monkeypatch) -> None:
    app_logger = _CaptureLogger()
    err_logger = _CaptureLogger()

    monkeypatch.setattr(main, "print_banner", lambda **_kwargs: None)
    monkeypatch.setattr(main, "main_menu", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(main.logging_engine, "get_app_logger", lambda: app_logger)
    monkeypatch.setattr(main.logging_engine, "get_error_logger", lambda: err_logger)
    monkeypatch.setattr(main.logging_engine, "ensure_trace", lambda extra=None: {"trace_id": "t-main", **dict(extra or {})})

    with pytest.raises(RuntimeError, match="boom"):
        main.main([])

    assert len(app_logger.messages) == 1
    assert "Unhandled application exception: RuntimeError: boom" in app_logger.messages[0][0]
    assert app_logger.messages[0][1]["trace_id"] == "t-main"
    assert app_logger.messages[0][1]["argv"] == []

    assert len(err_logger.messages) == 1
    assert "[APPLICATION] Unhandled application exception: RuntimeError: boom" in err_logger.messages[0][0]
    assert err_logger.messages[0][1]["source_category"] == "application"
