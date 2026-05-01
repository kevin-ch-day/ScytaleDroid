from __future__ import annotations

import json

from scytaledroid.Persistence import db_writer


def test_serialise_evidence_returns_sentinel_and_warns(monkeypatch) -> None:
    warnings: list[tuple[str, dict]] = []

    def _warn(msg: str, *, category: str | None = None, extra=None, **_kw) -> None:  # noqa: ANN001
        warnings.append((msg, {"category": category, "extra": extra}))

    monkeypatch.setattr(db_writer.log, "warning", _warn)

    payload = {"bad": object()}
    out = db_writer._serialise_evidence(payload, run_id=123)  # noqa: SLF001 - unit-test sentinel contract
    assert isinstance(out, str)
    obj = json.loads(out)
    assert obj["_serialization_type"] == "dict"
    assert "_serialization_error" in obj
    assert "_raw_repr" in obj
    assert warnings, "expected warning when evidence serialization fails"
    assert warnings[0][1]["category"] == "db"
    assert warnings[0][1]["extra"]["run_id"] == 123

