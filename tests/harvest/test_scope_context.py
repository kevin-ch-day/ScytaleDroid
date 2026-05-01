from scytaledroid.DeviceAnalysis.harvest import scope_context
from scytaledroid.DeviceAnalysis.harvest.models import InventoryRow


def _row(package: str, *, installer="com.android.vending", primary="/data/app/pkg", split=1) -> InventoryRow:
    return InventoryRow(
        raw={},
        package_name=package,
        app_label=package,
        installer=installer,
        category=None,
        primary_path=primary,
        profile_key=None,
        profile=None,
        version_name=None,
        version_code=None,
        apk_paths=[],
        split_count=split,
    )


def test_apply_default_scope_filters_non_user_partition():
    rows = [
        _row("com.play.app", primary="/system/app/foo"),
        _row("com.play.user", primary="/data/app/foo"),
    ]
    kept, excluded = scope_context.apply_default_scope(rows, set())
    assert len(kept) == 1
    assert kept[0].package_name == "com.play.user"
    assert excluded.get("non_root_paths") == 1


def test_estimated_files_counts_splits():
    rows = [_row("com.example", split=3)]
    assert scope_context.estimated_files(rows) == 3


def test_sample_names_limits_length():
    rows = [_row(f"pkg{i}") for i in range(5)]
    names = scope_context.sample_names(rows, limit=3)
    assert names == ["pkg0", "pkg1", "pkg2"]
