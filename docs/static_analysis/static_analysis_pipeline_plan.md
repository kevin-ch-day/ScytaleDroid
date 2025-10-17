# ScytaleDroid Static Analysis Pipeline Plan

## 1. Objectives
- Deliver a modular, scalable static-analysis pipeline that progresses from quick triage to deep inspection without regressing the current CLI workflows.
- Reuse and extend the existing manifest/permission summaries (see `scytaledroid/StaticAnalysis/core/pipeline.py`) while layering in richer, correlated findings.
- Support both JSON portability and first-class database persistence so investigators can query history, run comparisons, and drive future UI/API consumers.
- Maintain deterministic outputs, clear evidence pointers, reproducibility bundles, and high signal-to-noise across all severity gates.

## 1.1 Implementation status (Q4 FY25 snapshot)

- ✅ Detector runner and modular detectors are in place for manifest hygiene,
  permissions (Androguard-powered scoring), IPC exposure, provider ACLs,
  network surface (with NSC policy graphs), secrets, storage/backup, DFIR
  hints, WebView hardening, crypto misuse, dynamic loading, file I/O sinks,
  interaction surfaces, SDK inventory, native hardening, obfuscation, and a
  correlation layer.
- ✅ Pipeline runs persist pipeline traces, split-aware posture, differential
  metadata, and a reproducibility bundle (manifest digest, NSC serialisation,
  string-index sketch) inside the report metadata.
- ✅ CLI menu exposes quick/full profiles, evidence limits, and renders
  deterministic section summaries with badge/status alignment.
- 🚧 Persistence adapters are JSON-first today; DB schema design remains open
  pending infra alignment (see Section 7).
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
- ✅ Update CLI flows to expose scan profiles, render per-stage timings, and
  surface pipeline traces plus reproducibility bundles from saved reports.

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
  split composition, risk scoring, and final detector output with reproducible
  provenance chains.
- **Persistence Layer:** Interface `PersistenceAdapter` with implementations for
  JSON reports today and placeholders for future database writers. Reports embed
  pipeline metadata to support diff tooling even without a DB.

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
- **patterns.py:**
  - Provider-specific regexes (Google API key, AWS, Firebase, etc.).
  - Entropy-based heuristics, test-key suppression, whitelist handling.
- **detectors/** (new modular package):
  - `patterns.py` retains shared regexes/keyword sets for reuse across detectors.
  - `common.py` provides fragment helpers (context windows, evidence builders,
    entropy calculators) plus origin bucketing logic.
  - `fragment.py` houses per-fragment detectors (endpoints, secrets, cloud,
    feature flags, encoded payloads, entropy spikes).
  - `pairing.py` captures cross-fragment logic such as AWS key pairing.
  - `__init__.py` exposes registry helpers consumed by `post.py` so the
    orchestration layer stays concise and composable.
- **correlator.py:**
  - Link string hits to permissions, endpoints, components.
  - Produce hints like `overlay_permission + phishing_keyword`.
- Outputs cached in context for detectors (secrets, network, privacy) and correlation rules.

## 7. Persistence Design
### Database Schema (proposed)
- `static_analysis_runs`
  - `run_id` (PK), `apk_id`, `sha256`, `scan_profile`, `tool_version`, `config_hash`, `started_at`, `finished_at`, `status`, `notes`.
- `static_analysis_findings`
  - `finding_id` (PK), `run_id` (FK), `detector_id`, `severity_gate`, `masvs_category`, `title`, `rationale`, `correlation_chain` (JSON array), `evidence_pointer` (JSON), `remediation_hint`, `created_at`.
- `static_analysis_supporting_artifacts` (optional)
  - `artifact_id`, `finding_id`, `artifact_type`, `artifact_hash`, `payload` (JSON, small), `created_at`.
- `static_analysis_metrics`
  - `run_id`, `detector_id`, `metric_name`, `metric_value`, `unit`.

### Persistence Modes
- `json_only` *(current default)*: writes deterministic JSON reports (including
  `pipeline_trace` and `repro_bundle`) to `data/static_analysis/reports/`.
- `db_only`: insert runs/findings into DB, optionally skipping JSON output for
  volume-sensitive deployments.
- `dual_write`: both JSON and DB for validation phase.

### Migration Strategy
- Define migrations aligned with existing database tooling (confirm whether Alembic or custom migrations are standard).
- Version run schema changes via semantic versioning stored in `static_analysis_runs.tool_version`.

## 8. CLI Integration
- Add profile selector to `StaticAnalysis/cli/menu.py` (Quick vs Full; advanced flag for custom profile via CLI args).
- Display summary metrics post-scan: counts per severity, top detectors triggered, run ID/JSON path, pipeline duration, and
  reproducibility bundle hash.
- Modify report review flow:
  - If DB enabled, list recent runs from `static_analysis_runs` with filtering (severity, package, profile) and surface drift
    summaries using the stored `repro_bundle` hashes.
  - Legacy JSON viewer remains for `json_only` mode, exposing diff helpers for split posture and manifest drift.
- Provide export command to dump DB run to JSON for sharing (`static-analysis export --run RUN_ID`).

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
### Phase P0 – Infrastructure Readiness *(✅ delivered)*
- Finalized detector interface, context, and finding schema.
- Implemented string-analysis extractor prototype and cache.
- Landed JSON persistence (reports with `pipeline_trace` + `repro_bundle`).
- CLI exposes quick/full profiles and evidence controls.

### Phase P1 – Core Detectors & Correlation v1 *(✅ delivered)*
- Manifest baseline refactor, detector runner integration, and drift-aware
  correlation helpers shipped.
- Network surface/TLS, secrets, storage/backup, provider ACL, and permission
  analytics are active with deterministic evidence pointers.
- Correlation rules cover cleartext viability, IPC exfil paths, hard-coded
  credentials, backup exposure, crypto misuse, dynamic loading, and provider
  grant gaps.

### Phase P2 – Feature Expansion *(🚧 current focus)*
- Implement OEM sensitivity scoring, signer lineage timeline, endpoint role
  classifier, and consent lint based on the research backlog.
- Extend DFIR/export hints with minimal collection playbooks.
- Prototype database persistence adapters + migrations.
- Enhance CLI report views with severity breakdown, drift diff, and
  reproducibility hash surface area.

### Phase P3 – Hardening & Advanced Signals
- Add declarative rulepacks (Rego-lite), anomaly scoring (permission vector vs
  cohort), and anti-analysis fingerprinting.
- Optimize performance (parallel detector execution, caching) and add override
  workflow + FP analytics once DB mode lands.
- Document integration points for future UI/API consumers.

### Phase P4 – Validation & Release Prep
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
