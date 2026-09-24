"""Safe fixture compatibility without device, network or subprocess access."""

import hashlib
import json
import socket
import subprocess
from pathlib import Path

import pytest
from scytaledroid.DynamicAnalysis.tools.isolated_backend_fixture import (
    OUTCOMES,
    render_fixture_pack,
)


def payload(outcome="dormant"):
    return {
        "contract": "scytaledroid.isolated-fixture.v1",
        "target_kind": "controlled_fixture",
        "network": "disabled",
        "execution_authorized": False,
        "outcome": outcome,
        "events": [],
    }


@pytest.mark.parametrize("outcome", sorted(OUTCOMES))
def test_sealed_pack_is_honest_and_uses_existing_paths(tmp_path, monkeypatch, outcome):
    def denied(*a, **kw):
        pytest.fail("Fixture attempted execution/network")

    monkeypatch.setattr(subprocess, "Popen", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    path = render_fixture_pack(tmp_path / "pack", payload(outcome))
    m = json.loads(path.read_text())
    assert m["sealed_at"] and m["status"] == "fixture_only"
    assert m["dataset"]["countable"] is False and m["dataset"]["valid_dataset_run"] is False
    assert m["environment"]["execution_performed"] is False
    assert m["environment"]["isolation_validated"] is False
    assert m["qa"]["simulated_outcome"] == outcome
    assert m["target"]["base_apk_sha256"] is None
    a = m["artifacts"][0]
    assert not Path(a["relative_path"]).is_absolute()
    assert (
        hashlib.sha256((path.parent / a["relative_path"]).read_bytes()).hexdigest() == a["sha256"]
    )
    assert a["origin"] == "synthetic" and not m["observers"]


@pytest.mark.parametrize(
    "change",
    [
        {"target_kind": "consumer_phone"},
        {"device_serial": "ZY22JK89DR"},
        {"network": "internet"},
        {"execution_authorized": True},
    ],
)
def test_rejects_device_and_execution_before_writing(tmp_path, change):
    with pytest.raises(ValueError):
        render_fixture_pack(tmp_path / "pack", payload() | change)
    assert not (tmp_path / "pack").exists()


def test_existing_or_symlink_destination_is_not_overwritten(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(FileExistsError):
        render_fixture_pack(link, payload())
    assert list(real.iterdir()) == []
    path = render_fixture_pack(tmp_path / "pack", payload())
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        render_fixture_pack(path.parent, payload("install_failed"))
    assert path.read_bytes() == before


def test_network_outcome_contradiction_rejected(tmp_path):
    p = payload("no_network_observed")
    p["events"] = [{"offset_ms": 0, "kind": "network", "detail": "synthetic packet"}]
    with pytest.raises(ValueError, match="contradicts"):
        render_fixture_pack(tmp_path / "pack", p)


@pytest.mark.parametrize("offset", [-1, True, 3_600_001])
def test_invalid_event_offsets_rejected(tmp_path, offset):
    p = payload("activity_observed")
    p["events"] = [{"offset_ms": offset, "kind": "process", "detail": "synthetic"}]
    with pytest.raises(ValueError, match="offsets"):
        render_fixture_pack(tmp_path / "pack", p)
    assert not (tmp_path / "pack").exists()
