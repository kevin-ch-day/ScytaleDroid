from __future__ import annotations

from datetime import UTC, datetime

from scytaledroid.StaticAnalysis.modules.permissions import permission_matrix_view as matrix_view


def _profile(
    label: str,
    *,
    risk: float,
    fw_ds: set[str] | None = None,
    vendor_names: set[str] | None = None,
) -> dict[str, object]:
    package = label.lower().replace(" ", ".")
    return {
        "display_name": label,
        "label": label,
        "package": package,
        "risk": risk,
        "fw_ds": fw_ds or {"CAMERA"},
        "vendor_names": vendor_names or set(),
    }


def test_permission_matrix_uses_snapshot_and_stable_order_when_show_covers_all(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(matrix_view, "get_terminal_width", lambda: 240)
    monkeypatch.setattr(matrix_view.colors, "colors_enabled", lambda: False)

    profiles = [
        _profile("WhatsApp", risk=8.0),
        _profile("Facebook", risk=3.0),
        _profile("Instagram", risk=5.0),
    ]

    matrix_view.render_permission_matrix(
        profiles,
        scope_label="Research Dataset Alpha",
        show=10,
        snapshot_at=datetime(2026, 3, 28, 15, 4, tzinfo=UTC),
    )

    out = capsys.readouterr().out
    assert "Snapshot: 2026-03-28" in out
    assert "View: Apps 1–3/3" in out
    header_line = next(line for line in out.splitlines() if line.startswith("Permission"))
    facebook_index = header_line.index("Facebook")
    instagram_index = header_line.index("Instagram")
    whatsapp_index = header_line.index("WhatsApp")
    assert facebook_index < instagram_index < whatsapp_index


def test_permission_matrix_uses_top_risk_language_when_truncated(monkeypatch, capsys):
    monkeypatch.setattr(matrix_view, "get_terminal_width", lambda: 240)
    monkeypatch.setattr(matrix_view.colors, "colors_enabled", lambda: False)

    profiles = [
        _profile("Alpha", risk=1.0),
        _profile("Zulu", risk=9.0),
        _profile("Bravo", risk=7.0),
        _profile("Charlie", risk=3.0),
    ]

    matrix_view.render_permission_matrix(
        profiles,
        scope_label="Scope",
        show=2,
        snapshot_at="2026-03-28 9:04 AM",
    )

    out = capsys.readouterr().out
    assert "View: Top 1–2/4 by permission risk" in out
    header_line = next(line for line in out.splitlines() if line.startswith("Permission"))
    assert "Zulu" in header_line
    assert "Bravo" in header_line
    assert "Alpha" not in header_line


def test_permission_matrix_compacts_headers_and_prints_app_key(monkeypatch, capsys):
    monkeypatch.setattr(matrix_view, "get_terminal_width", lambda: 80)
    monkeypatch.setattr(matrix_view.colors, "colors_enabled", lambda: False)

    profiles = [
        _profile("Alpha One", risk=5.0),
        _profile("Beta Two", risk=4.0),
        _profile("Gamma Three", risk=3.0),
        _profile("Delta Four", risk=2.0),
        _profile("Epsilon Five", risk=1.0),
        _profile("Zeta Six", risk=0.5),
        _profile("Eta Seven", risk=0.4),
        _profile("Theta Eight", risk=0.3),
        _profile("Iota Nine", risk=0.2),
    ]

    matrix_view.render_permission_matrix(
        profiles,
        scope_label="Scope",
        show=9,
        snapshot_at="2026-03-28 9:04 AM",
    )

    out = capsys.readouterr().out
    header_line = next(line for line in out.splitlines() if line.startswith("Permission"))
    assert "AO" in header_line
    assert "BT" in header_line
    assert "App key:" in out
    assert "AO=Alpha One" in out
    assert "BT=Beta Two" in out
