from __future__ import annotations

from scytaledroid.Utils.IO.zip_safety import is_unsafe_zip_member_name


def test_is_unsafe_zip_member_name_rejects_traversal() -> None:
    assert is_unsafe_zip_member_name("../evil")
    assert is_unsafe_zip_member_name("foo/../../etc/passwd")
    assert is_unsafe_zip_member_name("/absolute")
    assert is_unsafe_zip_member_name("..\\windows")
    assert not is_unsafe_zip_member_name("AndroidManifest.xml")
    assert not is_unsafe_zip_member_name("res/xml/paths.xml")
