"""Transactional stage runner for static run summary persistence."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from scytaledroid.Utils.LoggingUtils import logging_utils as log


@dataclass(slots=True)
class PersistenceRetryPolicy:
    cached_schema_version: str
    max_txn_attempts: int
    max_lock_wait_attempts: int
    lock_wait_timeout_s: int
    retry_backoff_base_s: float
    retry_backoff_max_s: float


@dataclass(slots=True)
class PersistenceTransactionCallbacks:
    database_session: Callable[[], Any]
    apply_lock_wait_timeout: Callable[[object, int], None]
    bootstrap_persistence_transaction: Callable[..., Any]
    persist_findings_and_correlations_stage: Callable[..., None]
    persist_permission_and_storage_stage: Callable[..., None]
    persist_metrics_and_sections_stage: Callable[..., None]
    finalize_static_handoff_stage: Callable[..., bool]
    is_transient_persistence_error: Callable[[Exception], bool]
    looks_like_lock_wait_error: Callable[[Exception], bool]
    looks_like_db_disconnect: Callable[[Exception], bool]
    record_static_persistence_failure: Callable[..., None]
    update_static_run_metadata: Callable[..., None]
    update_static_run_status: Callable[..., None]


@dataclass(slots=True)
class PersistenceTransactionResult:
    run_id: int | None
    static_run_id: int | None
    persistence_failed: bool


def execute_persistence_transaction(
    *,
    run_package: str,
    run_id: int | None,
    static_run_id: int | None,
    stage_context: object,
    run_context: object,
    envelope: object,
    finding_totals: object,
    findings_context: object,
    metrics_context: object,
    outcome: object,
    ended_at_utc: str | None,
    abort_reason: str | None,
    abort_signal: str | None,
    policy: PersistenceRetryPolicy,
    callbacks: PersistenceTransactionCallbacks,
    db_errors: list[str],
    failure_state: dict[str, str | None],
    note_db_error: Callable[[str], None],
    raise_db_error: Callable[[str, str], None],
) -> PersistenceTransactionResult:
    persistence_failed = False
    attempt = 0
    while attempt < policy.max_txn_attempts:
        attempt += 1
        failure_state["stage"] = None
        db_errors.clear()
        created_run_id_this_attempt = False
        created_static_run_id_this_attempt = False
        outcome.run_id = int(run_id) if run_id is not None else None
        outcome.static_run_id = static_run_id
        outcome.baseline_written = False
        outcome.string_samples_persisted = 0
        outcome.persistence_retry_count = max(0, attempt - 1)
        attempt_error_start = len(outcome.errors)
        try:
            with callbacks.database_session() as db:
                callbacks.apply_lock_wait_timeout(db, policy.lock_wait_timeout_s)
                with db.transaction():
                    outcome.persistence_transaction_state = "in_txn"
                    bootstrap = callbacks.bootstrap_persistence_transaction(
                        run_id=run_id,
                        static_run_id=static_run_id,
                        outcome=outcome,
                        stage_context=stage_context,
                        run_context=run_context,
                        envelope=envelope,
                        finding_totals=finding_totals,
                        cached_schema_version=policy.cached_schema_version,
                        raise_db_error=raise_db_error,
                    )
                    run_id = bootstrap.run_id
                    static_run_id = bootstrap.static_run_id
                    created_run_id_this_attempt = bootstrap.created_run_id
                    created_static_run_id_this_attempt = bootstrap.created_static_run_id
                    outcome.run_id = int(run_id) if run_id is not None else None
                    outcome.static_run_id = static_run_id

                    callbacks.persist_findings_and_correlations_stage(
                        run_id=int(run_id) if run_id is not None else None,
                        static_run_id=static_run_id,
                        stage_context=stage_context,
                        findings_context=findings_context,
                        raise_db_error=raise_db_error,
                    )

                    callbacks.persist_permission_and_storage_stage(
                        run_id=int(run_id) if run_id is not None else None,
                        static_run_id=static_run_id,
                        stage_context=stage_context,
                        findings_context=findings_context,
                        raise_db_error=raise_db_error,
                    )

                    callbacks.persist_metrics_and_sections_stage(
                        run_id=int(run_id) if run_id is not None else None,
                        static_run_id=static_run_id,
                        stage_context=stage_context,
                        metrics_context=metrics_context,
                        findings_context=findings_context,
                        outcome=outcome,
                        note_db_error=note_db_error,
                        raise_db_error=raise_db_error,
                    )

                    if db_errors:
                        raise RuntimeError(db_errors[-1])
            handoff_failed = callbacks.finalize_static_handoff_stage(
                static_run_id=static_run_id,
                stage_context=stage_context,
                run_context=run_context,
                cached_schema_version=policy.cached_schema_version,
                outcome=outcome,
            )
            persistence_failed = handoff_failed
            outcome.persistence_transaction_state = "committed"
            break
        except Exception as exc:
            transient = callbacks.is_transient_persistence_error(exc)
            lock_wait = callbacks.looks_like_lock_wait_error(exc)
            db_disconnect = callbacks.looks_like_db_disconnect(exc)
            failure_stage = failure_state.get("stage")
            outcome.persistence_db_disconnect = bool(db_disconnect)
            outcome.persistence_exception_class = exc.__class__.__name__
            outcome.persistence_failure_stage = failure_stage
            compat_stage_names = getattr(stage_context, "compat_stage_names", None)
            if compat_stage_names is None:
                compat_stage_names = getattr(callbacks.bootstrap_persistence_transaction, "__globals__", {}).get(
                    "_COMPAT_PERSISTENCE_STAGES",
                    frozenset(),
                )
            if failure_stage and failure_stage in compat_stage_names:
                try:
                    outcome.compat_export_failed = True
                    outcome.compat_export_stage = failure_stage
                except Exception:
                    pass
            outcome.persistence_transaction_state = "rolled_back"
            outcome.persistence_retry_count = max(0, attempt - 1)
            lock_retry_budget_exhausted = lock_wait and attempt >= policy.max_lock_wait_attempts
            if transient and attempt < policy.max_txn_attempts and not lock_retry_budget_exhausted:
                if len(outcome.errors) > attempt_error_start:
                    del outcome.errors[attempt_error_start:]
                reset_identity = failure_stage in {"run.create", "static_run.create"}
                if reset_identity and created_run_id_this_attempt:
                    run_id = None
                if reset_identity and created_static_run_id_this_attempt:
                    static_run_id = None
                outcome.run_id = int(run_id) if run_id is not None else None
                outcome.static_run_id = int(static_run_id) if static_run_id is not None else None
                sleep_seconds = min(
                    policy.retry_backoff_max_s,
                    policy.retry_backoff_base_s * (2 ** max(0, attempt - 1)),
                )
                log.warning(
                    (
                        "Transient DB failure during static persistence "
                        f"for {run_package}; retrying full transaction "
                        f"(attempt={attempt}/{policy.max_txn_attempts}, "
                        f"lock_wait={int(lock_wait)} "
                        f"backoff={sleep_seconds:.2f}s): {exc}"
                    ),
                    category="static_analysis",
                )
                try:
                    time.sleep(sleep_seconds)
                except Exception:
                    pass
                continue

            persistence_failed = True
            retries_used = max(0, attempt - 1)
            message = (
                f"Static persistence transaction failed for {run_package}: {exc} "
                f"(retry_count={retries_used} transaction_state=rolled_back "
                f"stage={failure_stage or 'unknown'} db_disconnect={int(db_disconnect)} "
                f"db_lock_wait={int(lock_wait)})"
            )
            log.warning(message, category="static_analysis")
            if message not in outcome.errors:
                outcome.add_error(message)
            if static_run_id:
                try:
                    callbacks.record_static_persistence_failure(
                        static_run_id=int(static_run_id),
                        stage=failure_stage,
                        exc_class=exc.__class__.__name__,
                        exc_message=str(exc),
                        errors_tail=list(outcome.errors)[-10:],
                    )
                except Exception:
                    pass
                try:
                    callbacks.update_static_run_metadata(
                        int(static_run_id),
                        run_class="NON_CANONICAL",
                        non_canonical_reasons=json.dumps(["PERSISTENCE_ERROR"], ensure_ascii=True),
                    )
                except Exception:
                    pass
                try:
                    callbacks.update_static_run_status(
                        static_run_id=int(static_run_id),
                        status="FAILED",
                        ended_at_utc=ended_at_utc,
                        abort_reason=abort_reason or "persist_error",
                        abort_signal=abort_signal,
                    )
                except Exception:
                    pass
            static_run_id = None
            outcome.static_run_id = None
            break
    outcome.persistence_failed = persistence_failed
    return PersistenceTransactionResult(
        run_id=run_id,
        static_run_id=static_run_id,
        persistence_failed=persistence_failed,
    )


__all__ = [
    "PersistenceRetryPolicy",
    "PersistenceTransactionCallbacks",
    "PersistenceTransactionResult",
    "execute_persistence_transaction",
]
