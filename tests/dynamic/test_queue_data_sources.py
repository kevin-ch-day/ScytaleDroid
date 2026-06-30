from __future__ import annotations

from scytaledroid.DynamicAnalysis.menus import queue_data_sources


def test_resolve_live_build_drift_map_uses_identity_static_run_id_fallback(monkeypatch) -> None:
    monkeypatch.setattr(
        queue_data_sources,
        "load_plan_candidates",
        lambda package_name: (
            [
                {
                    "generated_at": "2026-06-30T00:00:00Z",
                    "version_name": "12.3.1-release.0",
                    "version_code": "312031000",
                    "identity": {
                        "version_code": "312031000",
                        "static_run_id": "5207",
                    },
                }
            ],
            None,
        ),
    )
    monkeypatch.setattr(
        queue_data_sources,
        "read_observed_version_code_details",
        lambda *_args, **_kwargs: {"version_code": "312040000"},
    )

    drift_map = queue_data_sources.resolve_live_build_drift_map(
        ["com.twitter.android"],
        device_serial="ZY22JK89DR",
    )

    assert drift_map == {
        "com.twitter.android": {
            "expected_version_code": "312031000",
            "expected_version_name": "12.3.1-release.0",
            "observed_version_code": "312040000",
            "static_run_id": "5207",
        }
    }
