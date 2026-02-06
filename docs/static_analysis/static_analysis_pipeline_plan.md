# ScytaleDroid Static Analysis Pipeline Plan

## 1. Objectives
- Deliver a modular, scalable static-analysis pipeline that progresses from quick triage to deep inspection without regressing the current CLI workflows.
- Reuse and extend the existing manifest/permission summaries (see `scytaledroid/StaticAnalysis/core/pipeline.py`) while layering in richer, correlated findings.
- Support both JSON portability and first-class database persistence so investigators can query history, run comparisons, and drive future UI/API consumers.
- Maintain deterministic outputs, clear evidence pointers, reproducibility bundles, and high signal-to-noise across all severity gates.

## 1.1 Implementation status (FY26 tightening pass)

- ✅ Detector runner and modular detectors are in place for manifest hygiene,
  permissions (catalog + governance-backed protection levels), IPC exposure, provider ACLs,
  network surface (with NSC policy graphs), secrets (validator-backed),
  storage/backup, DFIR hints, WebView hardening, crypto misuse, dynamic
  loading, file I/O sinks, interaction surfaces, SDK inventory, native
  hardening, obfuscation, the correlation layer, and the dedicated
  `StaticAnalysis/risk` package.
- ✅ Pipeline runs persist pipeline traces, split-aware posture, differential
  metadata, severity/category matrices, novelty indicators, workload profiles,
  and a reproducibility bundle (manifest digest, NSC serialisation,
  string-index sketch) inside the report metadata.
- ✅ CLI menu exposes quick/full profiles, hero banners, severity-aware summary
  cards, evidence limits, highlight ribbons, and deterministic section
  summaries with badge/status alignment.
- ✅ Canonical persistence ships with idempotent schema helpers, automatic
  promotion of provider exposures (BASE-002), lineage-aware diff baselines, and
  cross-run analytics reports.
- ✅ Permission scoring is centralised under ``scytaledroid.StaticAnalysis.risk``
  with consolidated weights, penalty/bonus handling, and shared helpers for
  CLI rendering, persistence, and downstream analysis.
- 🚧 OEM-sensitivity, signer lineage, and ML-backed endpoint classification are
  queued for Phase 2 once the foundational detectors stabilise.

## 2. Scope
### In scope
- ✅ Refactor `analyze_apk` into a detector pipeline with standardized
  interfaces, shared context, and correlation stages.
- ✅ Build detectors for network surface, secrets, storage/backup, WebView,
  crypto, provider ACLs, DFIR hints, dynamic behaviour, SDK/trackers,
  native/JNI, obfuscation/anti-analysis, and supporting string intelligence.
- ✅ Introduce a correlation engine that raises composite findings (e.g.,
  cleartext endpoints + permissive manifest) with explainable provenance and
  drift awareness.
- 🚧 Design and document database schemas (`static_analysis_runs`,
  `static_analysis_findings`, optional metrics/support tables) and persistence
  adapters.
- ✅ Update CLI flows to expose scan profiles, render per-stage timings, surface
  pipeline traces plus reproducibility bundles from saved reports, and surface
  analytics matrices/novelty indicators inline.

### Out of scope (for this iteration)
- Implementing dynamic analysis or runtime instrumentation.
- Shipping web/UI integrations (design should enable this later).
- Publishing raw secrets; only hashed snippets and evidence pointers are allowed.

## 3. Guiding Principles & Constraints
- **Determinism:** Same APK + configuration yields identical findings (excluding timestamps/IDs).
- **Evidence hygiene:** Store pointers and hashes, never raw secrets or large payloads.
- **Detector isolation:** Each detector has clear inputs/outputs, enabling parallelization and selective execution.
- **Pluggable persistence:** Support `json_only`, `db_only`, and `dual_write` modes for gradual rollout.
- **Performance:** Quick profile completes in ≤90s for large APKs; full profile ≤5 min on reference hardware.
- **Reliability:** P0 false positives ≤1% on the gold corpus; provide override workflow for analysts.

## 4. Architecture Overview
```
- APK → Initial Context (manifest, hashes, strings index, NSC policy) → Detector
  Runner → Correlation Engine → Persistence Adapter(s) → Reporting/UI
```
- **Pipeline Orchestrator:** `analyze_apk` assembles context (manifest tree,
  androguard handle, string index, network-security policy), dispatches
  detectors, merges results, triggers correlation rules, and hands off to
  persistence while capturing pipeline traces and reproducibility bundles.
- **Detector Packages:** Each detector lives under
  `scytaledroid/StaticAnalysis/detectors/` and declares profile metadata so the
  runner can emit deterministic `[skipped]` placeholders for quick scans.
- **String Intelligence:** `scytaledroid/StaticAnalysis/modules/string_analysis/`
  provides extractor + pattern catalog wiring secrets, network, storage, and
  correlation detectors to a shared index.
  - See `string_intelligence_explore.md` for exploratory metrics, issue flags,
    and CLI guidance when triaging raw string collections.
  - See `static_analysis_data_model.md` to understand how the collected strings
    and detector findings are persisted alongside other static-analysis tables.
- **Network Security Module:** `modules/network_security/` normalises NSC XML
  into policy graphs reused by network and correlation helpers.
- **Correlation Engine:** The `detectors/correlation/` package handles diffing,
  split composition, and final detector output with reproducible provenance
  chains, while `StaticAnalysis/risk/` owns composite score calculation and
  banding.
- **Persistence Layer:** Dual-write adapters feed deterministic JSON reports and
  the canonical database. `scytaledroid/StaticAnalysis/persistence/ingest.py`
  hosts the canonical writer (`ingest_baseline_payload`) along with idempotent
  helpers (`ensure_provider_plumbing`, `upsert_base002_for_session`). Reports
  embed pipeline metadata to support diff tooling even without a DB.

## 5. Detector Framework
### Detector Interface (conceptual)
```python
@dataclass
class DetectorResult:
    findings: list[Finding]
    metrics: dict[str, Any]
    debug: dict[str, Any]  # optional, not persisted by default

class Detector(Protocol):
    id: str
    name: str
    default_profiles: set[str]
    def run(self, ctx: DetectorContext) -> DetectorResult: ...
```

### DetectorContext
- APK metadata: path, size, hashes, androguard `APK` object.
- Manifest tree and pre-parsed manifest flags.
- String index (deduplicated literal table with origin pointers).
- Permission/component summaries (Stage 0 output) for reuse.
- Configuration toggles (profile, feature flags, performance limits).

### Finding Schema (shared across detectors)
- `finding_id` (stable slug derived from detector + signature).
- `title`, `description`, `severity_gate` (`P0`/`P1`/`P2`).
- `masvs_category` (NETWORK, PLATFORM, STORAGE, PRIVACY, CRYPTO, RESILIENCE).
- `detector_id`, `detector_version`.
- `evidence_pointer` (file path + line, manifest XPath, string hash, etc.).
- `supporting_data_hash` (SHA-256 or similar of structured payload stored separately).
- Optional remediation text and references (only persisted if short).

## 6. String Intelligence Subsystem
- **extractor.py:**
  - Harvest string literals from DEX (class/method references) and resources/assets.
  - Deduplicate and tag origins (`code:com.example.Class#method`, `res:values/strings.xml`).
  - Support streaming to handle large APKs.
- **constants.py:**
  - Provider-specific regexes (Google API key, AWS, Firebase, etc.).
  - Entropy heuristics, analytics vendor catalogs, and allow-lists centralised
    for reuse by the extractor and matcher.
- **aggregates.py / bucket_overview.py:**
  - Build the structured rollups consumed by the CLI (endpoint roots, API keys,
    entropy samples) while deduplicating hits and preserving evidence pointers.
- **matcher.py / network.py:**
  - Offer shared token classifiers, secret filters, and endpoint extraction
    helpers so tuning happens in one place and all consumers stay in sync.
- Outputs cached in context for detectors (secrets, network, privacy) and correlation rules.

## 7. Persistence Design
### Canonical schema (current)
- `apps` / `app_versions` – package + version metadata (name/code, SDK levels).
- `static_analysis_runs` – one row per scan with session, scope, SHA-256, profile,
  detector metrics, reproducibility bundle, analytics matrices, indicators, and
  workload payloads.
- `static_analysis_findings` – normalized findings with rule IDs, detector/module
  attribution, CVSS, MASVS control, evidence JSON, and evidence references.
- `static_fileproviders` / `static_provider_acl` – provider guard summaries and
  path-permission breakdowns for BASE-002 analytics.
- `endpoints`, `libraries`, `sdk_inventory`, etc. – canonical observations reused
  by the correlation/diff layers.

### CLI persistence modules (FY26 refactor)
- `StaticAnalysis/cli/persistence/run_summary.py` orchestrates the persistence
  pipeline and delegates to focused helpers (`metrics_writer`,
  `static_sections`, `permission_risk`).
- `StaticAnalysis/cli/db_persist.py` now re-exports the run summary entry point
  so existing imports continue to work.
- New unit coverage lives in `tests/persistence/` to protect helper behaviour
  (permission risk upserts, static string/baseline persistence).
- MASVS mapping (`masvs_mapper.py`) now covers provider exposures, diff signals
  (new exported components, newly added dangerous permissions, toggled
  cleartext/storage flags), which improves coverage of `PLATFORM-IPC-1`,
  `NETWORK-1`, and `PRIVACY-1` controls during CLI summaries and reporting.

Canonical helpers expose idempotent migrations (`ensure_provider_plumbing`) and
BASE-002 promotion (`upsert_base002_for_session`). Database views are not used;
the CLI and manual helper snippets rely on direct table queries.

## 8. CLI Integration
- Default run path launches immediately with tuned defaults (auto workers, INFO logging, cache purge) while an "Advanced options" branch exposes overrides for analysts who need to adjust thresholds or detector subsets.
- Add profile selector to `StaticAnalysis/cli/menu.py` (Quick vs Full; advanced flag for custom profile via CLI args).
- Display summary metrics post-scan: counts per severity, top detectors triggered, run ID/JSON path, pipeline duration, and
  reproducibility bundle hash.
- Modify report review flow:
  - If DB enabled, list recent runs from `static_analysis_runs` with filtering (severity, package, profile) and surface drift
    summaries using the stored `repro_bundle` hashes.
  - Legacy JSON viewer remains for `json_only` mode, exposing diff helpers for split posture and manifest drift.
- Provide export command to dump DB run to JSON for sharing (`static-analysis export --run RUN_ID`).
- Expose a Utilities → Housekeep action that prunes JSON/HTML artefacts beyond a 30-day retention window and resets cache/tmp
  directories ahead of repeat runs.

## 9. Correlation Engine
- Represent rules declaratively (e.g., YAML/JSON) to ease updates:
```yaml
- id: network_cleartext_viable
  severity: P0
  masvs: NETWORK
  requires:
    - detector: manifest
      finding: uses_cleartext_true
    - detector: network
      finding: http_endpoint_present
    - detector: permissions
      finding: internet_declared
  rationale: "Cleartext traffic viable on live endpoints. Triggered because manifest allows cleartext, HTTP endpoints were found, and INTERNET permission is present."
```
- Engine loads rules, maps detector findings by signature, and emits synthesized findings with provenance.
- Allow overrides/ignore rules via configuration.

## 10. Quality & Testing Strategy
- **Gold corpus:** curated APKs (real + test fixtures) covering each detector scenario; store expected findings for automated comparison.
- **Unit tests:** per detector using fixture contexts; verify severity/masvs tagging and evidence pointers.
- **Integration tests:** run pipeline on sample APKs, compare canonical output (hash-insensitive) to fixture expectations.
- **Performance tests:** measure per-detector runtime; set thresholds and alerts for regressions.
- **FP management:** capture analyst overrides in DB (e.g., `static_analysis_overrides` table) with rationale and expiration.

## 11. Dependencies & Tooling
- Confirm need for additional libraries: `pyaxmlparser`, `androguard` updates, `pyelftools` (native analysis), `lief` (optional), `networkx` (correlation graph?).
- Document platform compatibility matrix (Python versions, OS dependencies).
- Establish deterministic container or virtual environment configuration for CI/regression runs.

## 12. Implementation Roadmap
### Phase P0 – Infrastructure Readiness *(legacy label)*
- Finalized detector interface, context, and finding schema.
- Implemented string-analysis extractor prototype and cache.
- Landed JSON persistence (reports with `pipeline_trace` + `repro_bundle`).
- CLI exposes quick/full profiles and evidence controls.

### Phase P1 – Core Detectors & Correlation v1 *(legacy label)*
- Manifest baseline refactor, detector runner integration, and drift-aware
  correlation helpers shipped.
- Network surface/TLS, secrets, storage/backup, provider ACL, and permission
  analytics are active with deterministic evidence pointers.
- Correlation rules cover cleartext viability, IPC exfil paths, hard-coded
  credentials, backup exposure, crypto misuse, dynamic loading, and provider
  grant gaps.

### Phase P2 – Feature Expansion *(legacy label)*
- Implement OEM sensitivity scoring, signer lineage timeline, endpoint role
  classifier, and consent lint based on the research backlog.
- Extend DFIR/export hints with minimal collection playbooks.
- Prototype database persistence adapters + migrations.
- Enhance CLI report views with severity breakdown, drift diff, and
  reproducibility hash surface area.

### Phase P3 – Hardening & Advanced Signals *(legacy label)*
- Add declarative rulepacks (Rego-lite), anomaly scoring (permission vector vs
  baseline profiles), and anti-analysis fingerprinting.
- Optimize performance (parallel detector execution, caching) and add override
  workflow + FP analytics once DB mode lands.
- Document integration points for future UI/API consumers.

### Phase P4 – Validation & Release Prep *(legacy label)*
- Run gold corpus regression harness, tune rules, finalize severity policy.
- Complete developer/analyst documentation (how-to, schema references).
- Decide on default persistence mode and rollout strategy.
- Prepare CI jobs and release checklist.

## 13. Risks & Open Questions
- **Migration tooling:** confirm preferred approach (Alembic vs custom) to avoid divergence from existing DB practices.
- **Dependency approvals:** ensure additional libraries for native analysis or string parsing are acceptable across deployment environments.
- **Performance on large APKs:** string extraction and detector chaining must remain within resource budgets; plan for incremental optimization.
- **Correlation complexity:** rules must remain explainable; consider authoring tooling or linting to prevent conflicting rules.
- **Analyst workflow:** decide how overrides/acknowledgements feed back into reports and whether they affect future runs.

## 14. Next Actions
1. Review and ratify this plan with stakeholders (confirm detector priority, persistence expectations, and dependency budgets).
2. Lock detector/finding interface signatures and persistence schema (P0 deliverable).
3. Prepare initial migrations and configuration flags so implementation can begin without blocking on infra decisions.
