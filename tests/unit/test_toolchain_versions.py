from __future__ import annotations


def test_gather_toolchain_versions_shape() -> None:
    from scytaledroid.Utils.toolchain_versions import gather_toolchain_versions

    tc = gather_toolchain_versions()
    assert isinstance(tc, dict)
    assert "python" in tc
    assert "packages" in tc
    assert "tools" in tc
    assert "platform" in tc
    assert isinstance(tc["packages"], dict)
    # numpy should be present in the environment for this project.
    assert tc["packages"].get("numpy")

