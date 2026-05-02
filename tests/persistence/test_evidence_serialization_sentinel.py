from __future__ import annotations

import json

import pytest


def test_serialise_evidence_returns_sentinel_and_warns(monkeypatch) -> None:
    from scytaledroid.Database.db_func import evidence_json

    warnings: list[tuple[str, dict]] = []

    def _warn(msg: str, *, category: str | None = None, extra=None, **_kw) -> None:  # noqa: ANN001
        warnings.append((msg, {"category": category, "extra": extra}))

    monkeypatch.setattr(evidence_json.log, "warning", _warn)

    payload = {"bad": object()}
    out = evidence_json.serialise_evidence_for_db(payload, run_id=123)
    assert isinstance(out, str)
    obj = json.loads(out)
    assert obj["_serialization_type"] == "dict"
    assert "_serialization_error" in obj
    assert "_raw_repr" in obj
    assert warnings, "expected warning when evidence serialization fails"
    assert warnings[0][1]["category"] == "db"
    assert warnings[0][1]["extra"]["run_id"] == 123
