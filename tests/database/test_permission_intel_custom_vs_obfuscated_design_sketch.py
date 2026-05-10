"""Design-time examples: custom triage vs unknown/obfuscated (S2 taxonomy refinement).

These tests do **not** assert current production triage — they lock **documentation semantics**
for the split described in
``docs/database/permission_intel_classification_taxonomy_refinement.md``.

When ``custom_triage`` / ``unknown_obfuscated`` become real ``triage_status`` values or derived
report buckets, extend this module with golden-string classification tests.
"""

from __future__ import annotations

# Legitimate-looking app/vendor custom permissions (should not default to "malware-like").
EXAMPLES_CUSTOM_TRIAGE: tuple[str, ...] = (
    "com.example.app.permission.READ_DATA",
    "com.vendor.service.permission.BIND_SERVICE",
    "com.bank.mobile.permission.INTERNAL_BROADCAST",
)

# High-entropy / packed / suspicious namespace shapes (malware-research signal; not benign-by-default).
EXAMPLES_UNKNOWN_OBFUSCATED: tuple[str, ...] = (
    "lic.xplywwuwfeaqrlmzkizi.nebfhmeqksam.kvftqjv_oplus.permission.OPLUS_COMPONENT_SAFE",
)

# Brand-like / squatting — often separate governance from pure entropy.
EXAMPLES_BRAND_SPOOF_CANDIDATE_SHAPE: tuple[str, ...] = (
    "com.google.android.permission.FAKE_CUSTOM_THING",
)


def test_design_examples_are_documented_non_empty() -> None:
    assert EXAMPLES_CUSTOM_TRIAGE
    assert EXAMPLES_UNKNOWN_OBFUSCATED
    assert EXAMPLES_BRAND_SPOOF_CANDIDATE_SHAPE


def test_obfuscated_example_is_structurally_heavier_than_typical_custom() -> None:
    """Illustrative only — real classifiers use richer features than length."""
    bank = EXAMPLES_CUSTOM_TRIAGE[2]
    obf = EXAMPLES_UNKNOWN_OBFUSCATED[0]
    assert len(obf) > len(bank)
    assert obf.count(".") >= bank.count(".")


def test_brand_spoof_example_resembles_google_namespace() -> None:
    assert EXAMPLES_BRAND_SPOOF_CANDIDATE_SHAPE[0].lower().startswith("com.google.android.permission.")
