# Static Baseline Contract

Scope: static analysis only. This contract is the acceptance target for baseline audit runs.

## 1) Identity
- Artifact identity: `static_analysis_runs.sha256` (SHA-256 of analyzed APK artifact).
- Semantic identity: `(apps.package_name, app_versions.version_code, app_versions.version_name)`.
- Collision policy: semantic identity may map to multiple artifact hashes across time; hash remains authoritative per run.
- Category source for corpus outputs: `apps.profile_key`; fallback is `UNKNOWN`.

## 2) Idempotency
- Re-scanning the same artifact hash must not create a new app identity (`apps`/`app_versions` remain stable).
- Each execution creates a new `static_analysis_runs` row (new run ledger), but analytical outputs for same hash+config must be equal.
- `risk_scores` is upserted per `(package_name, session_stamp, scope_label)` and is the canonical scoring source.

## 3) Determinism
- Fixed inputs: same APK, same profile/config, same toolchain snapshot, same schema.
- Deterministic outputs: findings totals, detector counts, finding fingerprints, risk score + component breakdown (`risk_scores`), and category assignment.
- Allowed variance only: run identifiers and timestamp/path volatility (`run_id`, `created_at`, `updated_at`, explicit time fields, temporary absolute paths).

## 4) Success / Failure Semantics
- Run success: `static_analysis_runs.status='COMPLETED'` and required row present in `risk_scores` for the run session/package/scope.
- Required static run fields:
  - `app_version_id`, `session_stamp`, `scope_label`, `sha256`, `status`, `profile`, `findings_total`.
  - Reproducibility fields when available: `config_hash`, `pipeline_version`, `analysis_version`, `catalog_versions`, `run_signature`.
- Partial failure:
  - Run state remains non-complete (`FAILED`/`ABORTED`) and is auditable.
  - Persistence failures are recorded in `static_persistence_failures` (stage + exception metadata).

## 5) Config Pinning / Reproducibility
- Persisted config/version anchors are read from `static_analysis_runs`:
  - `config_hash`, `pipeline_version`, `analysis_version`, `catalog_versions`,
  - `tool_semver`, `tool_git_commit`, `schema_version`.
- Corpus tables must be generated from a frozen snapshot boundary and include these metadata fields in output manifests.

## 6) Noise Controls (Enforced)
- Persisted findings are capped per detector:
  - Default: `STATIC_FINDINGS_CAP_PER_DETECTOR=20`
  - Overrides: `STATIC_FINDINGS_CAP_OVERRIDES` (detector-specific caps).
- Severity is normalized to canonical labels: `High | Medium | Low | Info`.
- Taxonomy counters are normalized and persisted as metrics:
  - `findings.taxonomy.risk`
  - `findings.taxonomy.finding`
  - `findings.taxonomy.info`
