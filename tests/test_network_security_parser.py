from scytaledroid.StaticAnalysis.modules.network_security.parser import (
    extract_network_security_policy,
)


class FakeApk:
    def __init__(self, files):
        self._files = files

    def get_file(self, path):
        if path not in self._files:
            raise KeyError(path)
        return self._files[path]


def test_extract_network_security_policy_tracks_trust_anchors_and_pins():
    xml = """
    <network-security-config xmlns:android="http://schemas.android.com/apk/res/android">
      <base-config android:cleartextTrafficPermitted="false">
        <trust-anchors>
          <certificates android:src="system" />
        </trust-anchors>
      </base-config>
      <domain-config android:cleartextTrafficPermitted="true">
        <trust-anchors>
          <certificates android:src="user" />
        </trust-anchors>
        <pin-set android:expiration="2025-01-01">
          <pin android:digest="SHA-256">abcd==</pin>
        </pin-set>
        <domain android:includeSubdomains="true">example.com</domain>
      </domain-config>
    </network-security-config>
    """.strip().encode("utf-8")

    apk = FakeApk({"res/xml/network_security_config.xml": xml})
    policy = extract_network_security_policy(
        apk, manifest_reference="@xml/network_security_config"
    )

    assert policy.base_cleartext is False
    assert policy.trust_user_certificates is True
    assert policy.base_trust_anchors == ("system",)
    assert len(policy.domain_policies) == 1
    domain_policy = policy.domain_policies[0]
    assert domain_policy.domains == ("example.com",)
    assert domain_policy.include_subdomains is True
    assert domain_policy.user_certificates_allowed is True
    assert domain_policy.pinned_certificates[0]["expiration"] == "2025-01-01"
    assert domain_policy.pinned_certificates[0]["pins"][0]["digest"] == "SHA-256"
    assert domain_policy.pinned_certificates[0]["pins"][0]["value"] == "abcd=="
    assert domain_policy.trust_anchors == ("user",)
