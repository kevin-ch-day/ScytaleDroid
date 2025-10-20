"""DB helpers for static string analysis persistence.

This module mirrors the schema documented in
``docs/static_analysis/static_analysis_data_model.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, MutableMapping, Sequence, Union

from ...db_core import database_session, run_sql
from ...db_queries.static_analysis import string_analysis as queries


@dataclass(slots=True)
class StringSummaryRecord:
    """Payload describing aggregated string findings for a scope."""

    package_name: str
    session_stamp: str
    scope_label: str
    counts: Mapping[str, int]

    def to_parameters(self) -> dict[str, int | str]:
        counts = self.counts
        return {
            "package_name": self.package_name,
            "session_stamp": self.session_stamp,
            "scope_label": self.scope_label,
            "endpoints": int(counts.get("endpoints", 0)),
            "http_cleartext": int(counts.get("http_cleartext", 0)),
            "api_keys": int(counts.get("api_keys", 0)),
            "analytics_ids": int(counts.get("analytics_ids", 0)),
            "cloud_refs": int(counts.get("cloud_refs", 0)),
            "ipc": int(counts.get("ipc", 0)),
            "uris": int(counts.get("uris", 0)),
            "flags": int(counts.get("flags", 0)),
            "certs": int(counts.get("certs", 0)),
            "high_entropy": int(counts.get("high_entropy", 0)),
        }


@dataclass(slots=True)
class StringSample:
    """Representative string sample for a given findings bucket."""

    value_masked: str | None = None
    src: str | None = None
    tag: str | None = None
    source_type: str | None = None
    finding_type: str | None = None
    provider: str | None = None
    risk_tag: str | None = None
    confidence: str | None = None
    sample_hash: str | None = None
    root_domain: str | None = None
    resource_name: str | None = None
    scheme: str | None = None


SummaryRow = Union[StringSummaryRecord, Mapping[str, object]]
SampleRow = Union[StringSample, Mapping[str, object]]


def ensure_tables() -> bool:
    try:
        with database_session():
            run_sql(queries.CREATE_STRING_SUMMARY)
            run_sql(queries.CREATE_STRING_SAMPLES)
            run_sql(queries.CREATE_DOC_HOSTS_TABLE)
            for statement in (
                "ALTER TABLE static_string_samples ADD COLUMN source_type VARCHAR(16) NULL",
                "ALTER TABLE static_string_samples ADD COLUMN finding_type VARCHAR(32) NULL",
                "ALTER TABLE static_string_samples ADD COLUMN provider VARCHAR(64) NULL",
                "ALTER TABLE static_string_samples ADD COLUMN risk_tag VARCHAR(32) NULL",
                "ALTER TABLE static_string_samples ADD COLUMN confidence VARCHAR(16) NULL",
                "ALTER TABLE static_string_samples ADD COLUMN sample_hash CHAR(40) NULL",
                "ALTER TABLE static_string_samples ADD COLUMN root_domain VARCHAR(191) NULL",
                "ALTER TABLE static_string_samples ADD COLUMN resource_name VARCHAR(191) NULL",
                "ALTER TABLE static_string_samples ADD COLUMN scheme VARCHAR(32) NULL",
            ):
                try:
                    run_sql(statement)
                except Exception:
                    continue
            for host in _default_doc_hosts():
                try:
                    run_sql(queries.INSERT_DOC_HOST, (host,))
                except Exception:
                    continue
            try:
                run_sql(queries.CREATE_STRINGS_ROOT_BUCKET_INDEX)
            except Exception:
                pass
            for statement in (
                queries.CREATE_STRINGS_NORMALIZED_VIEW,
                queries.CREATE_DOC_POLICY_DRIFT_VIEW,
                queries.CREATE_STRINGS_EFFECTIVE_VIEW,
                queries.CREATE_STRING_FINDINGS_VIEW,
            ):
                try:
                    run_sql(statement)
                except Exception:
                    continue
        return True
    except Exception:
        return False


def tables_exist() -> bool:
    try:
        row1 = run_sql(queries.TABLE_EXISTS_SUMMARY, fetch="one")
        row2 = run_sql(queries.TABLE_EXISTS_SAMPLES, fetch="one")
        return bool(row1 and int(row1[0]) > 0 and row2 and int(row2[0]) > 0)
    except Exception:
        return False


def _summary_params(summary: SummaryRow) -> MutableMapping[str, object]:
    if isinstance(summary, StringSummaryRecord):
        return summary.to_parameters()
    base = dict(summary)
    return StringSummaryRecord(
        package_name=str(base.get("package_name", "")),
        session_stamp=str(base.get("session_stamp", "")),
        scope_label=str(base.get("scope_label", "")),
        counts={
            "endpoints": int(base.get("endpoints", 0)),
            "http_cleartext": int(base.get("http_cleartext", 0)),
            "api_keys": int(base.get("api_keys", 0)),
            "analytics_ids": int(base.get("analytics_ids", 0)),
            "cloud_refs": int(base.get("cloud_refs", 0)),
            "ipc": int(base.get("ipc", 0)),
            "uris": int(base.get("uris", 0)),
            "flags": int(base.get("flags", 0)),
            "certs": int(base.get("certs", 0)),
            "high_entropy": int(base.get("high_entropy", 0)),
        },
    ).to_parameters()


def upsert_summary(summary: SummaryRow) -> int | None:
    payload = _summary_params(summary)
    try:
        with database_session():
            run_sql(queries.INSERT_STRING_SUMMARY, payload)
            row = run_sql(
                queries.SELECT_SUMMARY_ID,
                (payload["package_name"], payload["session_stamp"], payload["scope_label"]),
                fetch="one",
            )
        return int(row[0]) if row else None
    except Exception:
        return None


def replace_top_samples(
    summary_id: int,
    samples: Mapping[str, Sequence[SampleRow]],
    *,
    top_n: int = 3,
) -> tuple[int, int]:
    """Replace samples for summary_id with top N per bucket.

    Returns (deleted, inserted).
    """
    deleted = 0
    inserted = 0
    try:
        with database_session():
            run_sql(queries.DELETE_SAMPLES_FOR_SUMMARY, (summary_id,))
            deleted = 1  # semantic marker (not actual count)
            for bucket, entries in samples.items():
                if not entries:
                    continue
                rank = 1
                for sample in list(entries)[: int(top_n)]:
                    record = _sample_to_mapping(sample)
                    value_masked = record.get("value_masked") or record.get("value")
                    src = record.get("src")
                    tag = record.get("tag")
                    source_type = record.get("source_type")
                    finding_type = record.get("finding_type")
                    provider = record.get("provider")
                    risk_tag = record.get("risk_tag")
                    confidence = record.get("confidence")
                    sample_hash = record.get("sample_hash")
                    root_domain = record.get("root_domain")
                    resource_name = record.get("resource_name")
                    scheme = record.get("scheme")
                    run_sql(
                        queries.INSERT_SAMPLE,
                        (
                            summary_id,
                            bucket,
                            str(value_masked)[:512] if value_masked is not None else None,
                            str(src)[:512] if src is not None else None,
                            (str(tag)[:64] if tag is not None else None),
                            rank,
                            (str(source_type)[:16] if source_type else None),
                            (str(finding_type)[:32] if finding_type else None),
                            (str(provider)[:64] if provider else None),
                            (str(risk_tag)[:32] if risk_tag else None),
                            (str(confidence)[:16] if confidence else None),
                            (str(sample_hash)[:40] if sample_hash else None),
                            (str(root_domain)[:191] if root_domain else None),
                            (str(resource_name)[:191] if resource_name else None),
                            (str(scheme)[:32] if scheme else None),
                        ),
                    )
                    inserted += 1
                    rank += 1
    except Exception:
        pass
    return deleted, inserted


def _sample_to_mapping(sample: SampleRow) -> MutableMapping[str, object]:
    if isinstance(sample, StringSample):
        return {
            "value_masked": sample.value_masked,
            "src": sample.src,
            "tag": sample.tag,
            "source_type": sample.source_type,
            "finding_type": sample.finding_type,
            "provider": sample.provider,
            "risk_tag": sample.risk_tag,
            "confidence": sample.confidence,
            "sample_hash": sample.sample_hash,
            "root_domain": sample.root_domain,
            "resource_name": sample.resource_name,
            "scheme": sample.scheme,
        }
    return dict(sample)


def seed_doc_hosts(hosts: Iterable[str]) -> int:
    """Insert the provided hosts into the documentary allow-list table."""

    unique = sorted({host.strip().lower() for host in hosts if host and host.strip()})
    if not unique:
        return 0
    inserted = 0
    try:
        with database_session():
            for host in unique:
                try:
                    run_sql(queries.INSERT_DOC_HOST, (host,))
                except Exception:
                    continue
                inserted += 1
    except Exception:
        return 0
    return inserted


def seed_doc_hosts_from_config(path: str | Path | None = None) -> int:
    """Seed documentary hosts from the string-noise configuration file."""

    if path is None:
        try:
            from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import (  # noqa: WPS433
                DEFAULT_POLICY_ROOT,
            )

            path = DEFAULT_POLICY_ROOT
        except Exception:
            path = None
    hosts = _default_doc_hosts(path)
    if not hosts:
        return 0
    return seed_doc_hosts(hosts)


def _default_doc_hosts(path: str | Path | None = None) -> tuple[str, ...]:
    if path is None:
        try:
            from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import (  # noqa: WPS433
                DEFAULT_POLICY_ROOT,
            )

            path = DEFAULT_POLICY_ROOT
        except Exception:
            return tuple()
    try:
        from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import (  # noqa: WPS433
            load_noise_policy,
        )
    except Exception:
        return tuple()
    try:
        policy = load_noise_policy(path)
    except Exception:
        return tuple()
    defaults = set()
    defaults.update(getattr(policy, "doc_host_defaults_full", frozenset()))
    defaults.update(getattr(policy, "doc_host_defaults_registrable", frozenset()))
    if not defaults:
        defaults.update(policy.hosts_documentary)
    hosts = {host.strip().lower() for host in defaults if host and host.strip()}
    return tuple(sorted(hosts))


__all__ = [
    "StringSummaryRecord",
    "StringSample",
    "SummaryRow",
    "SampleRow",
    "ensure_tables",
    "tables_exist",
    "upsert_summary",
    "replace_top_samples",
    "seed_doc_hosts",
    "seed_doc_hosts_from_config",
]

