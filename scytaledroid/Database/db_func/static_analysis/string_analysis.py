"""DB helpers for static string analysis persistence.

This module mirrors the schema documented in
``docs/static_analysis/static_analysis_data_model.md``.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Utils.LoggingUtils import logging_utils as log

from ...db_core import database_session, db_config, run_sql, run_sql_many
from ...db_queries.static_analysis import string_analysis as queries

_IS_SQLITE = str(db_config.DB_CONFIG.get("engine", "sqlite")).lower() == "sqlite"
_SAMPLE_BATCH_SIZE = int(os.getenv("SCYTALEDROID_STRING_SAMPLE_BATCH_SIZE", "250"))

SQLITE_CREATE_SUMMARY = """
CREATE TABLE IF NOT EXISTS static_string_summary (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  package_name TEXT NOT NULL,
  session_stamp TEXT NOT NULL,
  scope_label TEXT NOT NULL,
  run_id INTEGER NULL,
  static_run_id INTEGER NULL,
  endpoints INTEGER NOT NULL DEFAULT 0,
  http_cleartext INTEGER NOT NULL DEFAULT 0,
  api_keys INTEGER NOT NULL DEFAULT 0,
  analytics_ids INTEGER NOT NULL DEFAULT 0,
  cloud_refs INTEGER NOT NULL DEFAULT 0,
  ipc INTEGER NOT NULL DEFAULT 0,
  uris INTEGER NOT NULL DEFAULT 0,
  flags INTEGER NOT NULL DEFAULT 0,
  certs INTEGER NOT NULL DEFAULT 0,
  high_entropy INTEGER NOT NULL DEFAULT 0,
  placeholders_downgraded INTEGER NOT NULL DEFAULT 0,
  placeholders_suppressed INTEGER NOT NULL DEFAULT 0,
  doc_hosts_suppressed INTEGER NOT NULL DEFAULT 0,
  doc_cdns_suppressed INTEGER NOT NULL DEFAULT 0,
  trailing_punct_trimmed INTEGER NOT NULL DEFAULT 0,
  ws_wss_seen INTEGER NOT NULL DEFAULT 0,
  ipv6_seen INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(package_name, session_stamp, scope_label)
);
"""

SQLITE_CREATE_SAMPLES = """
CREATE TABLE IF NOT EXISTS static_string_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  summary_id INTEGER NOT NULL,
  static_run_id INTEGER NULL,
  bucket TEXT NOT NULL,
  value_masked TEXT NULL,
  src TEXT NULL,
  tag TEXT NULL,
  rank INTEGER NOT NULL DEFAULT 1,
  source_type TEXT NULL,
  finding_type TEXT NULL,
  provider TEXT NULL,
  risk_tag TEXT NULL,
  confidence TEXT NULL,
  sample_hash TEXT NULL,
  root_domain TEXT NULL,
  resource_name TEXT NULL,
  scheme TEXT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


@dataclass(slots=True)
class StringSummaryRecord:
    """Payload describing aggregated string findings for a scope."""

    package_name: str
    session_stamp: str
    scope_label: str
    counts: Mapping[str, int]
    run_id: int | None = None  # legacy FK to runs (read-only compatibility)
    static_run_id: int | None = None  # FK to static_analysis_runs

    def to_parameters(self) -> dict[str, object]:
        counts = self.counts
        return {
            "package_name": self.package_name,
            "session_stamp": self.session_stamp,
            "scope_label": self.scope_label,
            # Keep run_id nullable for legacy read-only compatibility.
            "run_id": int(self.run_id) if self.run_id is not None else None,
            "static_run_id": int(self.static_run_id) if self.static_run_id is not None else None,
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
            "placeholders_downgraded": int(counts.get("placeholders_downgraded", 0)),
            "placeholders_suppressed": int(counts.get("placeholders_suppressed", 0)),
            "doc_hosts_suppressed": int(counts.get("doc_hosts_suppressed", 0)),
            "doc_cdns_suppressed": int(counts.get("doc_cdns_suppressed", 0)),
            "trailing_punct_trimmed": int(counts.get("trailing_punct_trimmed", 0)),
            "ws_wss_seen": int(counts.get("ws_wss_seen", 0)),
            "ipv6_seen": int(counts.get("ipv6_seen", 0)),
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


SummaryRow = StringSummaryRecord | Mapping[str, object]
SampleRow = StringSample | Mapping[str, object]

def _table_has_column(table: str, column: str) -> bool:
    try:
        if _IS_SQLITE:
            rows = run_sql(f"PRAGMA table_info({table})", fetch="all")
            return any(row[1] == column for row in rows or ())
        rows = run_sql(
            "SELECT COUNT(*) FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = %s AND column_name = %s",
            (table, column),
            fetch="one",
        )
        return bool(rows and int(rows[0]) > 0)
    except Exception:
        return False


def _require_static_run_id(payload: Mapping[str, object], *, table: str) -> None:
    static_run_id = payload.get("static_run_id")
    if static_run_id is None or str(static_run_id).strip() == "":
        raise ValueError(
            "Legacy write blocked: static_run_id is required for canonical schema writes. "
            "Run migrations or regenerate static outputs."
        )
    if not _table_has_column(table, "static_run_id"):
        raise RuntimeError(
            f"Legacy schema detected: {table}.static_run_id is missing. "
            "Run migrations before persisting."
        )


def ensure_tables() -> bool:
    if _IS_SQLITE:
        try:
            row1 = run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='static_string_summary'",
                fetch="one",
            )
            row2 = run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='static_string_samples'",
                fetch="one",
            )
            row3 = run_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='doc_hosts'",
                fetch="one",
            )
            ok = bool(row1 and row2 and row3)
        except Exception:
            return False
    else:
        ok = True
        for name in (
            "static_string_summary",
            "static_string_samples",
            "doc_hosts",
        ):
            row = run_sql(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s",
                (name,),
                fetch="one",
            )
            present = bool(row and int(row[0]) > 0)
            ok = ok and present
    if not ok:
        log.warning(
            "string analysis tables missing; load a DB snapshot or apply migrations.",
            category="database",
        )
    return ok


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
    static_run = (
        int(base["static_run_id"])
        if base.get("static_run_id") is not None and str(base.get("static_run_id")).strip() != ""
        else None
    )
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
            "placeholders_downgraded": int(base.get("placeholders_downgraded", 0)),
            "placeholders_suppressed": int(base.get("placeholders_suppressed", 0)),
            "doc_hosts_suppressed": int(base.get("doc_hosts_suppressed", 0)),
            "doc_cdns_suppressed": int(base.get("doc_cdns_suppressed", 0)),
            "trailing_punct_trimmed": int(base.get("trailing_punct_trimmed", 0)),
            "ws_wss_seen": int(base.get("ws_wss_seen", 0)),
            "ipv6_seen": int(base.get("ipv6_seen", 0)),
        },
        run_id=(
            int(base["run_id"])
            if base.get("run_id") is not None and str(base.get("run_id")).strip() != ""
            else None
        ),
        static_run_id=static_run,
    ).to_parameters()


def upsert_summary(summary: SummaryRow) -> int | None:
    if _IS_SQLITE:
        payload = _summary_params(summary)
        _require_static_run_id(payload, table="static_string_summary")
        stmt = """
        INSERT INTO static_string_summary (
          package_name, session_stamp, scope_label, run_id, static_run_id,
          endpoints, http_cleartext, api_keys, analytics_ids, cloud_refs, ipc, uris, flags, certs,
          high_entropy, placeholders_downgraded, placeholders_suppressed, doc_hosts_suppressed,
          doc_cdns_suppressed, trailing_punct_trimmed, ws_wss_seen, ipv6_seen
        ) VALUES (
          %(package_name)s, %(session_stamp)s, %(scope_label)s, %(run_id)s, %(static_run_id)s,
          %(endpoints)s, %(http_cleartext)s, %(api_keys)s, %(analytics_ids)s, %(cloud_refs)s, %(ipc)s, %(uris)s, %(flags)s, %(certs)s,
          %(high_entropy)s, %(placeholders_downgraded)s, %(placeholders_suppressed)s, %(doc_hosts_suppressed)s,
          %(doc_cdns_suppressed)s, %(trailing_punct_trimmed)s, %(ws_wss_seen)s, %(ipv6_seen)s
        )
        ON CONFLICT(package_name, session_stamp, scope_label) DO UPDATE SET
          run_id=excluded.run_id,
          static_run_id=excluded.static_run_id,
          endpoints=excluded.endpoints,
          http_cleartext=excluded.http_cleartext,
          api_keys=excluded.api_keys,
          analytics_ids=excluded.analytics_ids,
          cloud_refs=excluded.cloud_refs,
          ipc=excluded.ipc,
          uris=excluded.uris,
          flags=excluded.flags,
          certs=excluded.certs,
          high_entropy=excluded.high_entropy,
          placeholders_downgraded=excluded.placeholders_downgraded,
          placeholders_suppressed=excluded.placeholders_suppressed,
          doc_hosts_suppressed=excluded.doc_hosts_suppressed,
          doc_cdns_suppressed=excluded.doc_cdns_suppressed,
          trailing_punct_trimmed=excluded.trailing_punct_trimmed,
          ws_wss_seen=excluded.ws_wss_seen,
          ipv6_seen=excluded.ipv6_seen;
        """
        try:
            with database_session():
                try:
                    run_sql(stmt, payload)
                except Exception:
                    fallback_stmt = """
                    INSERT INTO static_string_summary (
                      package_name, session_stamp, scope_label, run_id, static_run_id,
                      endpoints, http_cleartext, api_keys, analytics_ids, cloud_refs, ipc, uris, flags, certs,
                      high_entropy, placeholders_downgraded, placeholders_suppressed, doc_hosts_suppressed,
                      doc_cdns_suppressed, trailing_punct_trimmed, ws_wss_seen, ipv6_seen
                    ) VALUES (
                      %(package_name)s, %(session_stamp)s, %(scope_label)s, %(run_id)s, %(static_run_id)s,
                      %(endpoints)s, %(http_cleartext)s, %(api_keys)s, %(analytics_ids)s, %(cloud_refs)s, %(ipc)s, %(uris)s, %(flags)s, %(certs)s,
                      %(high_entropy)s, %(placeholders_downgraded)s, %(placeholders_suppressed)s, %(doc_hosts_suppressed)s,
                      %(doc_cdns_suppressed)s, %(trailing_punct_trimmed)s, %(ws_wss_seen)s, %(ipv6_seen)s
                    )
                    """
                    run_sql(fallback_stmt, payload)
                row = run_sql(
                    "SELECT id FROM static_string_summary WHERE package_name=%s AND session_stamp=%s AND scope_label=%s ORDER BY id DESC LIMIT 1",
                    (payload["package_name"], payload["session_stamp"], payload["scope_label"]),
                    fetch="one",
                )
            return int(row[0]) if row else None
        except Exception:
            return None
    payload = _summary_params(summary)
    _require_static_run_id(payload, table="static_string_summary")
    # Keep a copy for logging in case inserts fail.
    log_payload = {
        "package_name": payload.get("package_name"),
        "session_stamp": payload.get("session_stamp"),
        "scope_label": payload.get("scope_label"),
        "static_run_id": payload.get("static_run_id"),
    }
    try:
        with database_session():
            run_sql(queries.INSERT_STRING_SUMMARY, payload)
            row = None
            run_id = payload.get("static_run_id")
            if run_id is not None:
                row = run_sql(
                    queries.SELECT_SUMMARY_ID_BY_RUN,
                    (run_id, payload["scope_label"]),
                    fetch="one",
                )
            if not row:
                row = run_sql(
                    queries.SELECT_SUMMARY_ID,
                    (payload["package_name"], payload["session_stamp"], payload["scope_label"]),
                    fetch="one",
                )
            if not row:
                try:
                    from scytaledroid.Utils.LoggingUtils import logging_utils as log

                    log.warning(
                        "static_string_summary lookup returned no row after insert "
                        f"(package={payload.get('package_name')} session={payload.get('session_stamp')} "
                        f"scope={payload.get('scope_label')} run_id={payload.get('run_id')} "
                        f"static_run_id={payload.get('static_run_id')})",
                        category="db",
                    )
                except Exception:
                    pass
                return None
            return int(row[0])
    except Exception as exc:
        try:
            from scytaledroid.Utils.LoggingUtils import logging_utils as log
            log.warning(
                f"Failed to upsert static_string_summary for {payload.get('package_name')} "
                f"static_run_id={payload.get('static_run_id')} run_id={payload.get('run_id')}: {exc}",
                category="db",
            )
            log.debug(
                f"static_string_summary payload: {log_payload}",
                category="db",
            )
        except Exception:
            pass
        return None


def replace_top_samples(
    summary_id: int,
    samples: Mapping[str, Sequence[SampleRow]],
    *,
    top_n: int = 3,
    static_run_id: int | None = None,
) -> tuple[int, int]:
    """Replace samples for summary_id with top N per bucket.

    Returns (deleted, inserted).
    """
    if _IS_SQLITE:
        _require_static_run_id({"static_run_id": static_run_id}, table="static_string_samples")
        deleted = 0
        inserted = 0
        try:
            with database_session():
                run_sql("DELETE FROM static_string_samples WHERE summary_id=%s", (summary_id,))
                deleted = 1
                rows: list[tuple[object, ...]] = []
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
                        rows.append(
                            (
                                summary_id,
                                static_run_id,
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
                            )
                        )
                        rank += 1
                if rows:
                    stmt = """
                    INSERT INTO static_string_samples (
                      summary_id, static_run_id, bucket, value_masked, src, tag, rank,
                      source_type, finding_type, provider, risk_tag, confidence,
                      sample_hash, root_domain, resource_name, scheme
                    ) VALUES (
                      %s, %s, %s, %s, %s, %s, %s,
                      %s, %s, %s, %s, %s,
                      %s, %s, %s, %s
                    )
                    """
                    batch_size = max(_SAMPLE_BATCH_SIZE, 1)
                    for idx in range(0, len(rows), batch_size):
                        run_sql_many(stmt, rows[idx : idx + batch_size])
                    inserted = len(rows)
        except Exception:
            pass
        return deleted, inserted
    _require_static_run_id({"static_run_id": static_run_id}, table="static_string_samples")
    deleted = 0
    inserted = 0
    try:
        with database_session():
            run_sql(queries.DELETE_SAMPLES_FOR_SUMMARY, (summary_id,))
            deleted = 1  # semantic marker (not actual count)
            rows: list[tuple[object, ...]] = []
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
                    rows.append(
                        (
                            summary_id,
                            static_run_id,
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
                        )
                    )
                    rank += 1
            if rows:
                batch_size = max(_SAMPLE_BATCH_SIZE, 1)
                for idx in range(0, len(rows), batch_size):
                    run_sql_many(queries.INSERT_SAMPLE, rows[idx : idx + batch_size])
                inserted = len(rows)
    except Exception as exc:
        try:
            from scytaledroid.Utils.LoggingUtils import logging_utils as log
            log.warning(
                f"Failed to persist string samples for summary_id={summary_id} "
                f"static_run_id={static_run_id}: {exc}",
                category="db",
            )
            log.debug(
                "String sample insert failed for summary_id=%s static_run_id=%s payload_keys=%s",
                summary_id,
                static_run_id,
                list(samples.keys()),
                category="db",
            )
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
            from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import (
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
            from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import (
                DEFAULT_POLICY_ROOT,
            )

            path = DEFAULT_POLICY_ROOT
        except Exception:
            return tuple()
    try:
        from scytaledroid.StaticAnalysis.modules.string_analysis.allowlist import (
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
