"""Shared runtime-ML method/provenance descriptors.

These payloads are reporting metadata only. They make generated ML artifacts
explain their evidence and model roles without changing scoring behavior.
"""

from __future__ import annotations

from typing import Any

from . import ml_parameters_profile as config

METHOD_BASIS_VERSION = 1


def runtime_ml_method_basis(*, context: str) -> dict[str, Any]:
    """Return the stable method-basis payload embedded in ML artifacts."""

    return {
        "method_basis_version": METHOD_BASIS_VERSION,
        "context": str(context),
        "runtime_evidence": {
            "capture_unit": "package-filtered PCAP evidence pack",
            "feature_unit": "fixed-width PCAP time window",
            "feature_scope": "metadata-derived traffic shape and transport features",
            "content_visibility": "encrypted payloads are not decrypted by this pipeline",
            "interpretation": "runtime metadata complements static posture; it is not proof of exploitation",
        },
        "models": {
            config.MODEL_IFOREST: {
                "role": "primary_runtime_anomaly_score",
                "interpretation": "higher score indicates greater deviation from the training baseline",
            },
            config.MODEL_OCSVM: {
                "role": "secondary_robustness_check",
                "interpretation": "supporting novelty score; not the sole publication gate",
            },
        },
        "static_context": {
            "role": "attack_surface_context",
            "examples": ["permissions", "exported components", "network posture", "storage posture", "MASVS areas"],
            "interpretation": "static exposure is reported separately from observed runtime behavior",
        },
        "provenance_requirements": [
            "package_name",
            "version_code",
            "run_id",
            "static_run_id",
            "base_apk_sha256",
            "pcap_path",
            "capture_window",
            "activity_label",
        ],
        "known_caveats": [
            "app updates and function changes can introduce traffic feature drift",
            "thin baselines reduce confidence and should be surfaced as warnings",
            "duplicate build observations are useful evidence but should be disclosed",
            "One-Class SVM is sensitive to training composition and parameter choice",
        ],
        "references": [
            {
                "id": "holland_2022_pcapml",
                "title": "Towards Reproducible Network Traffic Analysis",
                "url": "https://arxiv.org/abs/2203.12410",
                "used_for": "network traffic reproducibility and metadata motivation",
            },
            {
                "id": "li_2022_foap",
                "title": "FOAP: Fine-Grained Open-World Android App Fingerprinting",
                "url": "https://www.usenix.org/conference/usenixsecurity22/presentation/li-jianfeng",
                "used_for": "encrypted Android traffic can expose app/activity structure",
            },
            {
                "id": "chen_2025_drift",
                "title": "Drift-oriented Self-evolving Encrypted Traffic Application Classification",
                "url": "https://arxiv.org/abs/2501.04246",
                "used_for": "app-update and function-change feature drift framing",
            },
            {
                "id": "owasp_masvs",
                "title": "OWASP Mobile Application Security Verification Standard",
                "url": "https://mas.owasp.org/MASVS/",
                "used_for": "static mobile attack-surface categories",
            },
        ],
    }


__all__ = ["METHOD_BASIS_VERSION", "runtime_ml_method_basis"]
