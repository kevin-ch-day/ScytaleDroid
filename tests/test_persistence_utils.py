from scytaledroid.StaticAnalysis.cli import cvss_v4, evidence, masvs_mapper, rule_mapping


def test_normalize_evidence_prefers_structured_entries():
    payload = [
        {"file": "AndroidManifest.xml", "detail": "exported component", "line": 42},
        {"path": "classes.dex", "detail": "secondary"},
    ]
    normalised = evidence.normalize_evidence(payload, detail_hint=" fallback ")
    assert normalised.path == "AndroidManifest.xml"
    assert normalised.offset == "42"
    assert normalised.detail == "exported component"
    assert normalised.entries


def test_rule_mapping_prefers_hint():
    result = rule_mapping.derive_rule_id(
        kind="diff_exported_components",
        module_id="manifest",
        evidence_path="AndroidManifest.xml",
        detail="exported component",
        rule_id_hint="BASE-IPC-COMP-NO-ACL",
    )
    assert result == "BASE-IPC-COMP-NO-ACL"


def test_summarise_controls_applies_precedence():
    entries = [
        ("BASE-CLR-001", {"kind": "network", "path": "manifest"}),
        ("BASE-CLR-001", {"kind": "network", "path": "other"}),
    ]
    summary = masvs_mapper.summarise_controls(entries)
    assert "NETWORK-1" in summary
    payload = summary["NETWORK-1"].payload()
    assert payload["status"] == "FAIL"
    assert len(payload["evidence"]) == 2


def test_rule_to_area_maps_control_namespace():
    assert masvs_mapper.rule_to_area("BASE-IPC-COMP-NO-ACL") == "PLATFORM"


def test_cvss_v4_scoring_matches_fallback_vectors():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"
    score = cvss_v4.score_vector(vector)
    assert score == 8.0
    bt_vector, bt_score, be_vector, be_score, bte_vector, bte_score, meta = cvss_v4.apply_profiles(
        vector, "Active", "enterprise"
    )
    assert "E:A" in bt_vector.split("/")
    assert bt_score is not None
    be_metrics = set(be_vector.split("/"))
    assert {"AR:H", "IR:H", "CR:H"}.issubset(be_metrics)
    assert be_score is not None
    assert "E:A" in bte_vector.split("/")
    assert bte_score is not None
    assert meta["threat"]["E"] == "A"


def test_cvss_v4_severity_band_mapping():
    assert cvss_v4.severity_band(10.0) == "Critical"
    assert cvss_v4.severity_band(9.0) == "Critical"
    assert cvss_v4.severity_band(8.9) == "High"
    assert cvss_v4.severity_band(7.0) == "High"
    assert cvss_v4.severity_band(6.9) == "Medium"
    assert cvss_v4.severity_band(4.0) == "Medium"
    assert cvss_v4.severity_band(3.9) == "Low"
    assert cvss_v4.severity_band(0.1) == "Low"
    assert cvss_v4.severity_band(0.0) == "None"
    assert cvss_v4.severity_band(None) is None
