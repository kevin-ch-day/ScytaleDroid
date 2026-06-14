from __future__ import annotations

import json

from scytaledroid.DeviceAnalysis import identity


def test_extract_signer_digests_normalizes_and_deduplicates() -> None:
    package_dump = """
        signer #1 certificate SHA-256 digest: AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99
        signer #2 certificate SHA-256 digest: aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899
        signing lineage digest sha256: AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899
    """

    assert identity.extract_signer_digests(package_dump) == [
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
    ]


def test_compute_signer_set_hash_is_order_stable() -> None:
    signer_a = "a" * 64
    signer_b = "b" * 64

    left = identity.compute_signer_set_hash([signer_b, signer_a, signer_b])
    right = identity.compute_signer_set_hash([signer_a, signer_b])

    assert left == right
    assert left is not None
    assert len(left) == 64


def test_resolve_hex_digest_checks_top_level_then_embedded_extras() -> None:
    payload = {
        "signer_cert_digest": "",
        "extras": json.dumps(
            {
                "signer_cert_digest": "AA" * 32,
                "split_membership_hash": "BB" * 32,
            }
        ),
    }

    assert identity.resolve_hex_digest(payload, "signer_cert_digest") == ("aa" * 32)
    assert identity.resolve_hex_digest(payload, "split_membership_hash") == ("bb" * 32)


def test_compute_split_membership_hash_is_order_stable() -> None:
    paths = ["/data/app/pkg/base.apk", "/data/app/pkg/split_config.en.apk"]
    reversed_paths = list(reversed(paths))

    assert identity.compute_split_membership_hash(paths) == identity.compute_split_membership_hash(reversed_paths)
