from __future__ import annotations

from scytaledroid.Database.db_func.harvest import install_sets


def test_artifact_set_hash_v1_orders_base_then_splits_by_name() -> None:
    members = (
        install_sets.InstallSetMember(
            apk_id=2,
            role="split",
            split_name="split_config.xhdpi",
            sha256="c" * 64,
        ),
        install_sets.InstallSetMember(
            apk_id=1,
            role="base",
            split_name="base",
            sha256="b" * 64,
        ),
        install_sets.InstallSetMember(
            apk_id=3,
            role="split",
            split_name="split_config.arm64_v8a",
            sha256="a" * 64,
        ),
    )

    assert install_sets.artifact_set_hash_v1(members) == (
        "d1b2463f7903c7f311649dddf5e1a584423523334d2db6b409654494c9f9a549"
    )


def test_upsert_install_set_ignores_records_without_exactly_one_base(monkeypatch) -> None:
    def fail_ensure_tables() -> None:  # pragma: no cover - should not be called
        raise AssertionError("ensure_tables should not be called")

    monkeypatch.setattr(install_sets, "ensure_tables", fail_ensure_tables)
    record = install_sets.InstallSetRecord(
        session_label="session-a",
        package_name="com.example",
        device_serial="SERIAL",
        snapshot_id=None,
        app_id=None,
        version_code="1",
        version_name="1.0",
        status="clean",
        generated_at_utc=None,
        receipt_root=None,
        members=(
            install_sets.InstallSetMember(
                apk_id=2,
                role="split",
                split_name="split_config.xhdpi",
                sha256="c" * 64,
            ),
        ),
    )

    assert install_sets.upsert_install_set(record) is None
