import re
from pathlib import Path


ALLOWLIST = {
    "scytaledroid/DeviceAnalysis/adb_client.py",
}

ADB_SUBPROCESS_RE = re.compile(r"subprocess\.(run|Popen|call)\([^)]*['\"]adb['\"]", re.S)


def test_no_adb_subprocess_outside_adb_client():
    root = Path(__file__).resolve().parents[2]
    scytaledroid_dir = root / "scytaledroid"
    offenders = []
    for path in scytaledroid_dir.rglob("*.py"):
        rel = path.relative_to(root).as_posix()
        if rel in ALLOWLIST:
            continue
        content = path.read_text(encoding="utf-8")
        if "subprocess" not in content:
            continue
        if ADB_SUBPROCESS_RE.search(content):
            offenders.append(rel)
    assert not offenders, f"adb subprocess usage outside adb_client: {offenders}"
