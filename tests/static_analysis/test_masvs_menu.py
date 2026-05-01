from __future__ import annotations

from scytaledroid.StaticAnalysis.cli.menus import masvs_menu


def test_select_static_run_prefers_canonical_static_runs(monkeypatch):
    monkeypatch.setattr(
        masvs_menu.core_q,
        "run_sql",
        lambda *_a, **_k: [
            {
                "static_run_id": 569,
                "package_name": "org.telegram.messenger",
                "app_label": "Telegram",
                "session_label": "qa-telegram-full-1",
                "status": "COMPLETED",
            },
            {
                "static_run_id": 568,
                "package_name": "com.google.android.apps.messaging",
                "app_label": "Messages",
                "session_label": "qa-messages-fast-1",
                "status": "COMPLETED",
            },
        ],
    )
    monkeypatch.setattr(masvs_menu.prompt_utils, "prompt_text", lambda *_a, **_k: "569")

    selected = masvs_menu._select_static_run()

    assert selected == (569, "org.telegram.messenger", "qa-telegram-full-1")


def test_render_masvs_summary_menu_uses_static_run_summary(monkeypatch, capsys):
    monkeypatch.setattr(
        masvs_menu,
        "_select_static_run",
        lambda: (569, "org.telegram.messenger", "qa-telegram-full-1"),
    )

    calls = {"count": 0}

    def _fake_many(ids):
        calls["count"] += 1
        assert ids == [569]
        return (
            569,
            [
                {
                    "area": "NETWORK",
                    "high": 0,
                    "medium": 1,
                    "low": 0,
                    "info": 0,
                    "control_count": 1,
                    "cvss": {
                        "worst_score": 6.8,
                        "worst_severity": "Medium",
                        "worst_identifier": "network_cleartext",
                        "average_score": 6.8,
                        "band_counts": {"Medium": 1},
                    },
                    "quality": {
                        "coverage_status": "ok",
                        "risk_index": 5.3,
                        "cvss_coverage": 1.0,
                        "risk_components": {
                            "inputs": {
                                "severity_density_norm": 0.25,
                                "cvss_band_score": 0.5,
                                "cvss_intensity": 0.75,
                            }
                        },
                    },
                }
            ],
        )

    captured: list[tuple[list[str], list[list[str]]]] = []

    monkeypatch.setattr(masvs_menu, "fetch_db_masvs_summary_static_many", _fake_many)
    monkeypatch.setattr(
        masvs_menu.table_utils,
        "render_table",
        lambda headers, rows, *args, **kwargs: captured.append((headers, rows)),
    )
    monkeypatch.setattr(masvs_menu.prompt_utils, "press_enter_to_continue", lambda *_a, **_k: None)

    masvs_menu.render_masvs_summary_menu()

    out = capsys.readouterr().out
    assert "static_run_id=569 | org.telegram.messenger | qa-telegram-full-1" in out
    assert "Pass percentage" in out
    assert calls["count"] == 1
    assert captured
    assert captured[0][1][0][0] == "Network"

