from __future__ import annotations

from pathlib import Path

import pytest
from scytaledroid.Publication.profile_v3_metrics import (
    ProfileV3Error,
    compute_profile_v3_per_app,
)


def test_profile_v3_metrics_reject_run_id_outside_evidence_root(tmp_path: Path) -> None:
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()

    with pytest.raises(ProfileV3Error) as excinfo:
        compute_profile_v3_per_app(
            included_run_ids=["../outside-run"],
            evidence_root=evidence_root,
            catalog={},
            allow_multi_model=False,
        )

    assert excinfo.value.code == "PROFILE_V3_UNSAFE_RUN_ID"
