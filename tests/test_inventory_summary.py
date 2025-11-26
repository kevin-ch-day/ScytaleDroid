import sys
from io import StringIO
import contextlib
import types


def _fake_pkg(pkg_name, partition, category=None, source=None, split=1):
    return {
        "package_name": pkg_name,
        "partition": partition,
        "profile_name": category,
        "source": source,
        "base_code_path": "/data/app/" + pkg_name,
        "code_paths": ["/data/app/" + pkg_name] * split,
    }


def test_inventory_summary_no_duplicate_partitions(capsys):
    # Avoid heavy imports/circular deps by stubbing device_service before import.
    stub_device_service = types.SimpleNamespace()
    sys.modules["scytaledroid.DeviceAnalysis.services.device_service"] = stub_device_service

    from scytaledroid.DeviceAnalysis import inventory  # imported late to avoid circulars

    rows = [
        _fake_pkg("app.user", "Data", category="User", source="Play Store"),
        _fake_pkg("app.oem", "Product", category="OEM", source="Sideload"),
        _fake_pkg("app.sys", "System", category="System", source="Play Store"),
        _fake_pkg("app.apex", "Apex", category="Mainline", source="Play Store"),
    ]

    buf = StringIO()
    with contextlib.redirect_stdout(buf):
        inventory._render_inventory_summary(rows)  # type: ignore[attr-defined]

    out = buf.getvalue()

    # Ensure partition labels appear once, not duplicated under multiple headings
    assert out.count("/data") == 1
    assert out.count("/product") == 1
    assert out.count("/system") == 1
    assert out.count("/apex") == 1
