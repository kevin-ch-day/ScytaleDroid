from __future__ import annotations

import pytest
from scytaledroid.DynamicAnalysis.ml import artifact_bundle_writer
from scytaledroid.DynamicAnalysis.ml.publication_bundle import validation


@pytest.mark.parametrize("resolver", [artifact_bundle_writer._dynamic_run_dir, validation._dynamic_run_dir])
@pytest.mark.parametrize("run_id", ["../escape", "/tmp/escape", "nested/run", " run-1 ", "", None])
def test_publication_run_resolvers_reject_unsafe_ids(resolver, run_id: object) -> None:
    with pytest.raises(ValueError, match="Unsafe dynamic run_id"):
        resolver(run_id)
