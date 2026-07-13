from __future__ import annotations

from scytaledroid.DynamicAnalysis.ml import ml_parameters_profile as config
from scytaledroid.DynamicAnalysis.ml.method_basis import runtime_ml_method_basis


def test_runtime_ml_method_basis_documents_model_roles_and_caveats() -> None:
    payload = runtime_ml_method_basis(context="unit_test")

    assert payload["method_basis_version"] >= 1
    assert payload["context"] == "unit_test"
    assert payload["models"][config.MODEL_IFOREST]["role"] == "primary_runtime_anomaly_score"
    assert payload["models"][config.MODEL_OCSVM]["role"] == "secondary_robustness_check"
    assert payload["runtime_evidence"]["content_visibility"] == "encrypted payloads are not decrypted by this pipeline"
    assert "static_run_id" in payload["provenance_requirements"]
    assert any("traffic feature drift" in caveat for caveat in payload["known_caveats"])
