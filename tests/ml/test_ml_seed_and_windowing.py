from __future__ import annotations

from scytaledroid.DynamicAnalysis.ml.identity import derive_seed, identity_key_from_plan
from scytaledroid.DynamicAnalysis.ml.windowing import WindowSpec, iter_windows


def test_identity_key_from_plan_prefers_full_identity_tuple():
    plan = {
        "run_identity": {
            "run_signature_version": "v1",
            "run_signature": "abc",
            "artifact_set_hash": "def",
            "base_apk_sha256": "0123",
        }
    }
    assert identity_key_from_plan(plan) == "v1:abc:def:0123"


def test_derive_seed_is_stable_32bit():
    seed1 = derive_seed("k1")
    seed2 = derive_seed("k1")
    seed3 = derive_seed("k2")
    assert seed1 == seed2
    assert seed1 != seed3
    assert 0 <= seed1 <= 0xFFFFFFFF


def test_iter_windows_drops_partial_tail():
    spec = WindowSpec(window_size_s=10.0, stride_s=5.0)
    windows, dropped = iter_windows(23.0, spec)
    # Full windows: [0,10), [5,15), [10,20)
    assert windows == [(0.0, 10.0), (5.0, 15.0), (10.0, 20.0)]
    # Starts at 15 and 20 do not fit a full 10s window in 23s.
    assert dropped == 2

