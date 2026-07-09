from __future__ import annotations


def test_classify_telegram_cidr_destination_as_first_party() -> None:
    from scytaledroid.DynamicAnalysis.ip_context import classify_ip_destination

    ctx = classify_ip_destination("149.154.175.51", package_name="org.telegram.messenger")

    assert ctx["cidr"] == "149.154.160.0/20"
    assert ctx["owner_class"] == "first_party"
    assert ctx["role_class"] == "telegram_datacenter_transport"
    assert ctx["confidence"] == "high"
    assert ctx["basis"] == "curated_cidr"
    assert ctx["match_type"] == "CIDR"
    assert ctx["first_party"] is True


def test_classify_telegram_cidr_is_package_scoped() -> None:
    from scytaledroid.DynamicAnalysis.ip_context import classify_ip_destination

    ctx = classify_ip_destination("149.154.175.51", package_name="com.example.other")

    assert ctx["owner_class"] == "unknown"
    assert ctx["first_party"] is False
