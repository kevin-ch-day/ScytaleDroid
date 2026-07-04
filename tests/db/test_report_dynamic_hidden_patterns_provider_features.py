from __future__ import annotations

from scripts.db import report_dynamic_hidden_patterns as report
from scytaledroid.Database.db_core import db_queries as core_q


def test_load_provider_features_uses_fileprovider_authorities_when_acl_rows_absent(
    monkeypatch,
) -> None:
    package = "com.example.alpha"

    def _fake_run_sql(sql, params=None, **kwargs):
        del params, kwargs
        normalized = " ".join(str(sql).split()).lower()
        if "from static_provider_acl" in normalized:
            return []
        if "from static_fileproviders" in normalized:
            return [
                {
                    "package_name": package,
                    "authority": "com.example.alpha.provider",
                    "grant_uri_permissions": 1,
                },
                {
                    "package_name": package,
                    "authority": "com.example.alpha.provider.cache",
                    "grant_uri_permissions": 0,
                },
            ]
        raise AssertionError(f"unexpected sql: {sql}")

    monkeypatch.setattr(core_q, "run_sql", _fake_run_sql)

    out = report._load_provider_features({package})

    assert out[package]["provider_authority_count"] == 2
    assert out[package]["grant_uri_permissions_count"] == 1


def test_load_provider_features_unions_acl_and_fileprovider_authorities(monkeypatch) -> None:
    package = "com.example.beta"

    def _fake_run_sql(sql, params=None, **kwargs):
        del params, kwargs
        normalized = " ".join(str(sql).split()).lower()
        if "from static_provider_acl" in normalized:
            return [
                {
                    "package_name": package,
                    "authority": "com.example.beta.provider",
                    "metadata": '{"grant_uri_permissions": true}',
                }
            ]
        if "from static_fileproviders" in normalized:
            return [
                {
                    "package_name": package,
                    "authority": "com.example.beta.provider",
                    "grant_uri_permissions": 1,
                },
                {
                    "package_name": package,
                    "authority": "com.example.beta.provider.images",
                    "grant_uri_permissions": 0,
                },
            ]
        raise AssertionError(f"unexpected sql: {sql}")

    monkeypatch.setattr(core_q, "run_sql", _fake_run_sql)

    out = report._load_provider_features({package})

    assert out[package]["provider_authority_count"] == 2
    assert out[package]["grant_uri_permissions_count"] >= 1
