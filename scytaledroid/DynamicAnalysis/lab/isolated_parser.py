"""Runs only in the disposable worker's unprivileged parser namespace."""

import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import zipfile
from pathlib import Path


def main():
    assert os.getuid() == 65534
    assert not Path("/dev/kvm").exists() and not Path("/home/systemadmin").exists()
    assert not Path("/sdk").exists() and not Path("/control").exists()
    assert [n for _, n in socket.if_nameindex()] == ["lo"]
    receipt = json.loads(Path("/input/measurement.json").read_text())
    lo = receipt["t0_epoch_ns"]
    hi = receipt["window_end_epoch_ns"]
    pcap = Path("/input/capture.pcap")

    # Capture is inside one worker clock domain. Decimal boundaries retain ns precision.
    def fmt(ns: int) -> str:
        return f"{ns // 1_000_000_000}.{ns % 1_000_000_000:09d}"

    display = f"frame.time_epoch >= {fmt(lo)} && frame.time_epoch < {fmt(hi)}"
    args = [
        "/usr/bin/tshark",
        "-n",
        "-r",
        str(pcap),
        "-Y",
        display,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=a",
    ]
    fields = [
        "frame.time_epoch",
        "frame.len",
        "dns.flags.response",
        "dns.qry.name",
        "ip.dst",
        "ipv6.dst",
    ]
    for field in fields:
        args += ["-e", field]
    p = subprocess.run(args, capture_output=True, text=True, timeout=90, check=True)
    rows = [line.split("\t") for line in p.stdout.splitlines() if line]
    destinations = set()
    dns = set()
    dns_count = 0
    for row in rows:
        row += [""] * (6 - len(row))
        if row[2] == "0":
            dns_count += 1
            dns.update(x for x in row[3].split(",") if x)
        for x in (row[4] + "," + row[5]).split(","):
            if x:
                try:
                    destinations.add(str(ipaddress.ip_address(x)))
                except ValueError:
                    pass
    metadata = {}
    with zipfile.ZipFile("/input/fixture.apk") as z:
        infos = z.infolist()
        assert len(infos) < 10000
        metadata = {
            "zip_members": len(infos),
            "manifest_present": any(i.filename == "AndroidManifest.xml" for i in infos),
            "extracted": False,
        }
    summary = {
        "contract": "window_measurement_v2",
        "window_filter": display,
        "window_seconds": 300,
        "packet_count": len(rows),
        "byte_count": sum(int(r[1]) for r in rows),
        "dns_query_packet_count": dns_count,
        "dns_names": sorted(dns),
        "destination_count": len(destinations),
        "destinations": sorted(destinations),
        "first_packet_timestamp": rows[0][0] if rows else None,
        "last_packet_timestamp": rows[-1][0] if rows else None,
        "pcap_sha256": hashlib.sha256(pcap.read_bytes()).hexdigest(),
        "apk_sha256": hashlib.sha256(Path("/input/fixture.apk").read_bytes()).hexdigest(),
        "apk_metadata": metadata,
        "logcat_bytes": Path("/input/logcat.txt").stat().st_size,
        "parser_uid": os.getuid(),
        "parser_interfaces": socket.if_nameindex(),
        "parser_has_kvm": Path("/dev/kvm").exists(),
        "parser_tools": subprocess.check_output(
            ["/usr/bin/tshark", "--version"], text=True
        ).splitlines()[0],
        "parser_stderr": p.stderr,
        "drop_counter": "unavailable; no zero-drop claim",
        "no_automatic_sham_subtraction": True,
    }
    Path("/output/window_metrics.json").write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
