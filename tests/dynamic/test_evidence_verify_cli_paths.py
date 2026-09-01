from __future__ import annotations

from pathlib import Path

from scytaledroid.DynamicAnalysis.tools.evidence.verify_cli import (
    _pcap_path_from_manifest,
)


def test_verify_cli_does_not_follow_manifest_or_symlink_pcap_outside_run(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"outside")
    (run_dir / "linked.pcap").symlink_to(outside)
    manifest = {
        "artifacts": [
            {
                "type": "pcapdroid_capture",
                "relative_path": "../outside.pcap",
            }
        ]
    }

    assert _pcap_path_from_manifest(run_dir, manifest) is None
