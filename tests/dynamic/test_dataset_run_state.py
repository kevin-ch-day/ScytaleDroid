from __future__ import annotations

from scytaledroid.DynamicAnalysis.pcap.dataset_tracker import DatasetTrackerConfig
from scytaledroid.DynamicAnalysis.services import dataset_run_state


def _valid_baseline_runs(count: int) -> list[dict[str, object]]:
    return [
        {
            "valid_dataset_run": True,
            "counts_toward_quota": True,
            "run_profile": "baseline_idle",
        }
        for _ in range(count)
    ]


def test_protocol_from_runs_prefers_manual_when_script_template_missing(monkeypatch) -> None:
    cfg = DatasetTrackerConfig()
    monkeypatch.setattr(dataset_run_state, "resolved_template_for_package", lambda _pkg: None)

    suggested_profile, suggested_slot = dataset_run_state._protocol_from_runs(
        package_name="bbc.mobile.news.ww",
        runs=_valid_baseline_runs(int(cfg.baseline_required)),
        cfg=cfg,
    )

    assert suggested_profile == "interaction_manual"
    assert suggested_slot == int(cfg.baseline_required) + 1


def test_protocol_from_runs_prefers_manual_under_paper3_policy_even_when_template_exists(monkeypatch) -> None:
    cfg = DatasetTrackerConfig()
    monkeypatch.setattr(
        dataset_run_state,
        "resolved_template_for_package",
        lambda _pkg: "news_reader_basic_v1",
    )

    suggested_profile, suggested_slot = dataset_run_state._protocol_from_runs(
        package_name="bbc.mobile.news.ww",
        runs=_valid_baseline_runs(int(cfg.baseline_required)),
        cfg=cfg,
    )

    assert suggested_profile == "interaction_manual"
    assert suggested_slot == int(cfg.baseline_required) + 1


def test_load_dataset_run_state_ignores_legacy_identity_runs(monkeypatch) -> None:
    cfg = DatasetTrackerConfig()
    payload = {
        "apps": {
            "com.facebook.katana": {
                "runs": [
                    {
                        "run_id": "legacy-facebook",
                        "valid_dataset_run": True,
                        "paper_eligible": True,
                        "counts_toward_quota": True,
                        "run_profile": "baseline_idle",
                        "version_code": "471216151",
                        "base_apk_sha256": "oldsha",
                        "ended_at": "2026-05-14T20:54:11+00:00",
                    }
                ]
            }
        }
    }
    monkeypatch.setattr(
        dataset_run_state,
        "_load_tracker_payload",
        lambda _cfg: ("ok", payload, payload),
    )
    monkeypatch.setattr(
        dataset_run_state,
        "default_resolve_tracker_run_identity",
        lambda _pkg, row: (
            str(row.get("version_code") or "") or None,
            str(row.get("base_apk_sha256") or "") or None,
        ),
    )
    monkeypatch.setattr(
        dataset_run_state,
        "scope_tracker_runs_to_active_identity",
        lambda _pkg, runs, resolve_tracker_run_identity_fn: {
            "active_identity": ("472143276", "newsha"),
            "active_runs": [],
            "valid_runs": list(runs),
            "legacy_runs": list(runs),
            "legacy_valid": 1,
            "legacy_builds": 1,
        },
    )
    monkeypatch.setattr(
        dataset_run_state,
        "build_scoped_dataset_counts",
        lambda _pkg, runs, cfg, resolve_tracker_run_identity_fn: {
            "technical_valid_active": 0,
            "baseline_countable": 0,
            "interactive_countable": 0,
            "baseline_extra": 0,
            "baseline_low_signal_supplemental": 0,
            "interactive_extra": 0,
            "interactive_low_signal_supplemental": 0,
        },
    )
    monkeypatch.setattr(dataset_run_state, "_evidence_state", lambda _pkg: ("ok", 1))

    state = dataset_run_state.load_dataset_run_state("com.facebook.katana", config=cfg)

    assert state.counts.total_runs == 0
    assert state.counts.baseline_valid_runs == 0
    assert state.counts.interactive_valid_runs == 0
    assert state.quota_counted_local == 0
    assert state.paper_eligible_local == 0
    assert state.historical_valid_runs == 1
    assert state.historical_build_count == 1
