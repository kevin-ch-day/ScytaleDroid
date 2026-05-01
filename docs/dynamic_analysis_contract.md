# Dynamic Analysis Contract (v1)

This document defines the contract, data model, and evidence rules for dynamic
analysis in ScytaleDroid. It is intentionally tool-agnostic and focused on
research-grade reproducibility.

Freeze/profile notes:
- Evidence packs are authoritative.
- The DB is derived/rebuildable (accelerator), not ground truth.
- Freeze/profile ML selects runs from a dataset-level freeze manifest and consumes evidence packs only.

Paper/export note:

- evidence packs are the authoritative per-run record for the older paper-style
  dynamic export lane as well
- anything derived after freeze, including ML outputs and DB rows, is not part
  of the frozen dataset itself

## 0. Cross-Cutting Rules

- **Run identity:** `dynamic_run_id` is a UUIDv4. It is not derived from inputs.
- **Baseline resolution:** dynamic runs must be anchored to a resolved static
  baseline derived from **artifact identity** (package + hashes). `static_run_id`
  is always recorded and displayed for auditability, but it is **not** required
  input in the normal operator flow.
- **Schema versioning:** `run_manifest_version` starts at `1`. Bump only for
  breaking changes; readers should remain backward compatible when possible.
- **Determinism:** Folder layout and filenames are stable. Do not embed
  timestamps in artifact filenames; timestamps are allowed only as manifest
  metadata.
- **Evidence integrity (per-run):** Artifacts should be registered in the manifest
  with relative paths. Per-artifact hashes are best-effort and should be treated
  as an audit aid, not the dataset immutability anchor. Only immutable artifacts
  should carry `sha256` in the registry; mutable note/log artifacts should omit
  hashes.
- **Evidence integrity (dataset-level):** Freeze/profile mode relies on a checksummed dataset
  freeze manifest (`included_run_checksums`) to verify immutability of frozen inputs.
- **Redaction:** Raw artifacts are preserved. Redaction occurs only in
  summaries or rendered output.
- **Status model:** `success`, `degraded`, `failed`.

## 1. Core Abstraction: Dynamic Run

A **Dynamic Run** is a controlled execution of a target app while observers
collect artifacts. The output is an **Evidence Pack** anchored by a manifest
that can be re-processed without re-running the app.

### Run definition fields

- **Target:** package, version, hashes, optional `apk_id`
- **Environment:** device/emulator identity, OS build, runtime context
- **Scenario:** descriptive label (e.g., `cold_start`, `basic_usage`)
- **Observers:** list of enabled observers with per-observer status
- **Artifacts:** stable registry with hashes and provenance
- **Outputs:** analysis summaries and human-readable notes
- **Status:** `success` | `degraded` | `failed`

### Artifact identity (baseline linkage)

Dynamic runs **must** identify the artifact being tested:

- `base_apk_sha256` (single-APK identity)
- `artifact_set_hash` (split/bundle identity; required when splits exist)

If the installed artifact does not match the resolved baseline, the run must
**pause and require operator action** (run static analysis now, select a
different baseline, or cancel). No silent continuation.

## 2. Evidence Pack Layout

Evidence packs are stored under:

```
output/evidence/dynamic/<dynamic_run_id>/
  run_manifest.json
  artifacts/
  analysis/
  notes/                # optional
```

Each run produces a single, atomic folder. Future grouping (e.g.
`session_<id>/run_<id>/`) is optional and must preserve the same internal layout.

## 3. Run Manifest (v1)

`run_manifest.json` is the canonical, machine-readable record of the run. It
must include:

- `run_manifest_version: 1`
- `dynamic_run_id: UUIDv4`
- `created_at`, `started_at`, `ended_at` timestamps
- `status: success | degraded | failed`
- `target` (package, version, hashes, optional `apk_id`)
- `environment` (device/emulator identifiers, OS build)
- `scenario` (id, label, optional notes)
- `observers` (id, status, error, artifacts[])
- `artifacts` (global registry, sorted by relative path)
- `outputs` (analysis summaries, notes)

### Dataset validity block (freeze/profile mode)

Dataset validity is recorded in the manifest and treated as authoritative:
- `dataset.tier` (e.g., `"dataset"`)
- `dataset.valid_dataset_run: true|false`
- `dataset.invalid_reason_code` (when invalid)
- `dataset.countable: true|false` (counts toward quota)

Trainability is separate from validity:
- `dataset.low_signal: true|false` (flag only; does not invalidate)
- `dataset.low_signal_reasons: []` (optional)

### Artifact registry

Every artifact entry contains:

- `relative_path`
- `type`
- `sha256` (optional; only for immutable artifacts)
- `size_bytes` (optional)
- `produced_by` (observer id)

Artifact registry entries must be sorted by `relative_path` for deterministic
output. An optional `manifest_sha256` may be stored after the manifest is
finalized.

## 3.1 Dataset freeze (selector + immutability anchor)

The frozen dataset is selected by a dataset-level freeze manifest:
- Canonical anchor: `data/archive/dataset_freeze.json`
- `included_run_ids` lists the exact run_ids included for the frozen cohort.
- `included_run_checksums` provides SHA-256 checksums for the frozen inputs per included run.

Freeze rules:
- The freeze manifest does not mutate evidence packs.
- After freeze, do not recompute frozen artifacts for the included set.

Required frozen inputs for a valid included run:

- `run_manifest.json`
- `inputs/static_dynamic_plan.json`
- canonical PCAP referenced by the manifest
- `analysis/summary.json`
- `analysis/pcap_report.json`
- `analysis/pcap_features.json`

## 4. Status Semantics

- **success:** Scenario completed; all required observers succeeded.
- **degraded:** Scenario completed; one or more observers failed or produced
  partial output.
- **failed:** Scenario did not execute cleanly or a valid evidence pack could
  not be produced.

If an observer fails, still emit its folder and a `observer_error.json` (or
`error.txt`) file so the run remains explainable. The manifest must capture the
failure and associated error message.

## 5. Observer Interface Contract

Observers are modular plugins that do not depend on scenario logic. Each
observer must provide:

- `start(run_ctx) -> handle`
- `stop(handle) -> list[artifact_records]`

Observers write artifacts into `artifacts/` and return metadata to be registered
in the manifest.

## 6. Scenario Contract

Scenarios are **descriptive**, not procedural. Initial labels include:

- `cold_start`
- `basic_usage`
- `permission_trigger`
- `background_idle` (optional)

Manual execution is acceptable initially. The orchestrator should prompt the
operator to begin and end the scenario and record start/end timestamps plus
operator notes in the manifest.

## 7. Operator Workflow (Manual-First)

The operator flow is intentionally minimal and repeatable. Tool choices are
preconfigured; the operator only selects the app, scenario, and observers.

### Before the run (2–5 minutes)

- Choose the target app (already installed or installed now).
- Choose the scenario (e.g., `basic_usage`).
- Choose observers (e.g., `network_capture`, `system_logs`).
- Confirm the resolved static baseline (package, version, hash, `static_run_id`).
  If the baseline is missing or ambiguous, the run must not start.

### Step 1: Put the device in a known state

The system should establish a clean baseline before recording:

- Clear app data (`pm clear`).
- Reset permissions or record the current permission state.
- Confirm network state (Wi-Fi/cellular).
- Capture OS + device metadata.

This ensures the run captures behavior attributable to the scenario.

### Step 2: Start the run (recording begins)

When the operator starts the run:

- A `dynamic_run_id` is created.
- A new evidence folder is created.
- Observers start (network capture, log streaming).
- Timestamps are recorded.

No analysis happens here—only capture.

### Step 3: Use the app (the scenario)

The system prompts with the scenario and a rough duration. The operator drives
the app manually (e.g., open settings, scroll feeds, trigger permissions). The
system records only start/end timestamps and optional operator notes.

### Step 4: Stop the run (recording ends)

When the operator stops:

- Observers stop and write raw artifacts.
- Hashes are computed.
- The run manifest is finalized.

### Step 5: Post-processing (summarize, not interpret)

A post-processor reads raw captures and emits:

- `analysis/summary.json`
- `analysis/summary.md`

These link findings back to raw artifacts for reproducibility.

## 8. Post-Processing Outputs (Minimum v1)

Post-processing can be rerun without re-executing the app. Minimum outputs:

```
analysis/summary.json
analysis/summary.md
```

`summary.json` must include:

- Run metadata (target/environment/scenario/observers)
- Destinations observed (domains/IPs when available)
- Flags:
  - `cleartext_http_detected: true | false | unknown`
  - `tls_mitm_suspected: true | false | unknown`
- `notable_log_signals: []`

## 9. Profile v3 capture minima

Current human-visible minima for Profile v3:

- required per-app runs:
  - `baseline_idle`
  - `interaction_scripted`
- fixed windowing:
  - window size `10s`
  - stride `5s`
- target duration per run:
  - `180s`
- minimum duration for dataset-tier validity:
  - `120s`
- minimum windows per run:
  - `20`
- minimum PCAP bytes:
  - `baseline_idle`: `0B`
  - `interaction_scripted`: `40,000B`

Manual interaction may still be used operationally, but scripted interaction
remains the default publication-grade path unless an explicit re-scope says
otherwise.
- Evidence pointers (artifact paths + sha256)

## 8.1 Telemetry windows (time-series readiness)

Dynamic telemetry should be segmentable into fixed-length windows suitable for
time-series modeling. Windowing metadata (window size, overlap, sampling rate)
must be recorded in analysis outputs so experiments are reproducible and
comparable across runs.

`summary.md` provides a 10–20 line human-readable narrative suitable for paper
drafting.

## 8.2 ML outputs (derived, versioned)

Freeze/profile ML writes derived outputs under the evidence pack:

```
output/evidence/dynamic/<dynamic_run_id>/analysis/ml/v<ml_schema_version>/
  anomaly_scores_iforest.csv
  anomaly_scores_ocsvm.csv
  model_manifest.json
  ml_summary.json
```

After freeze, ML outputs must be treated as immutable:
- No overwrites for included runs.
- Bug fixes require bumping the ML schema/output version and writing to a new path.

## 9. Redaction Rules (Summaries Only)

Summaries must never print raw secrets. Redact the following:

- Authorization headers and tokens (Bearer, cookies, session IDs)
- Refresh tokens, API keys
- Unintentionally captured email/phone identifiers

Use `<REDACTED>` or prefix-only redaction when correlation is needed. Raw
artifacts remain unchanged inside the evidence pack.

## 10. Integration Notes

- `apk_id` is optional in the manifest and should be populated when available.
- The dynamic pipeline must operate without database connectivity; DB linkage
  can follow once the run loop is stable.

## 11. Recommended Module Map (Tool-Agnostic)

To keep implementation consistent and flexible, the dynamic system should be
implemented with the following modules and responsibilities:

### 11.1 Dynamic Run Core

Goal: every run produces a consistent evidence pack.

- `RunContext` (run id, paths, target identity, environment info)
- `RunManifest` (machine-readable metadata + artifact registry)
- `EvidencePackWriter` (folder layout, manifest IO, hashing)
- `Status` model (`success` / `degraded` / `failed`)

### 11.2 Orchestrator (Control Layer)

Goal: coordinate the run lifecycle end-to-end without assuming tools.

- `RunOrchestrator.begin_run()`
- `start_observers()`
- `execute_scenario()` (manual initially)
- `stop_observers()`
- `finalize_run()` (hash artifacts, write manifest, trigger post-processing)

### 11.3 Target Manager

Goal: install/launch/clean app state reliably.

- `install_target(apk_path | apk_id)`
- `uninstall_target()` (optional)
- `clear_app_data(package)`
- `launch_app(package)`
- `capture_target_fingerprint()` (package/version/hash)

### 11.4 Environment Manager (“Sandbox-Lite”)

Goal: capture device fingerprint and enforce baseline state.

- Capture OS/device metadata (model, build, Android version)
- Enforce baseline network state (Wi-Fi/cellular, proxy settings)
- Optional reset strategies:
  - Emulator snapshot restore (best)
  - Device reset steps (clear data + permissions)

### 11.5 Scenario System (Manual-First)

Goal: standardize usage semantics without automation lock-in.

- `ScenarioDescriptor` (label, intent, duration)
- `ScenarioRunnerManual` (operator prompts, timestamps, notes)
- Optional future: `ScenarioRunnerAutomated`

### 11.6 Observers (Pluggable Capture Modules)

Goal: passive capture that can be swapped later.

- Observer interface: `start(run_ctx)` / `stop(handle) -> ArtifactRecords`
- Minimum observers:
  - `SystemLogObserver` (logcat capture)
  - `NetworkCaptureObserver` (pcap/pcapng capture or placeholder)
- Optional next:
  - `PermissionsObserver` (before/after runtime perms)
  - `StorageSnapshotObserver` (post-run snapshot/diff)

### 11.7 Post-Processor (Interpretation Layer)

Goal: turn raw evidence into paper-ready facts without re-running apps.

- `Summarizer` reads artifacts and emits:
  - `analysis/summary.json`
  - `analysis/summary.md`
- Apply redaction rules only in summaries (not during capture).

### 11.8 Integration Glue (Optional Early)

Goal: keep pipeline file-first but ready for DB linkage.

- Optional `apk_id` linkage in the manifest
- Deferred DB writes for `dynamic_runs` and `dynamic_run_artifacts`

## 12. Sandbox Guidance (Now vs Later)

### 12.1 Sandbox-Lite (recommended now)

For research-grade runs today, “sandbox” means:

- Controlled app state resets between runs
- Network + log capture enabled
- Reproducible, comparable evidence packs

This can be achieved with:

- Real device + reset steps
- Emulator with snapshots

### 12.2 Full Sandbox (future capability)

Later phases may add:

- Instrumentation/hooking (Frida/Xposed)
- Deep filesystem/API tracing
- Anti-tamper research
- Large-scale automation

These are not required for the initial dynamic analysis engine.

## 13. Heavy-Weight (Lab-Grade) Architecture Outline

When you are ready to move beyond sandbox-lite, the lab-grade design focuses on
repeatable orchestration, stronger isolation, and evidence governance rather
than kernel-level malware sandboxing.

### 13.1 Lab Controller (Long-Running Service)

Owns run scheduling, device inventory, configuration, and health monitoring.
Runs are treated as queued jobs so they can be retried, resumed, and audited.

### 13.2 Run Ledger + Queue (DB-Backed)

Suggested tables (conceptual):

- `dynamic_runs` (run_id, status, timestamps, scenario, target, device_id)
- `dynamic_run_artifacts` (run_id, artifact_type, path, sha256, size)
- `dynamic_observer_results` (run_id, observer_id, status, error)
- `dynamic_run_events` (run_id, event_time, event_type, message)
- `dynamic_run_claims` (host/user/pid/token)

### 13.3 Device Manager (Hardware Control Plane)

Maintains device registry (serial/model/OS) and enforces baseline state:
clears app data, resets or records permissions, configures proxy/DNS, and
captures battery/thermal state when needed.

### 13.4 Target Manager (Lifecycle + Identity)

Installs/uninstalls targets, launches apps, verifies package/version/signature,
and maintains an APK staging cache with hashes and prerequisites.

### 13.5 Network Lab (Host-Owned Capture & Control)

Captures per-run traffic (pcap), DNS, and TLS metadata; optionally enforces
allow/deny lists, proxy routing, and shaping. This is the primary isolation
lever in a laptop lab.

### 13.6 Scenario Engine (Manual → Guided → Automated)

Supports manual runs, guided checklists, and automated UI later. Scenario
definitions should be stored as YAML/JSON descriptors with labels, durations,
required observers, and optional step prompts.

### 13.7 Observer Framework (Multi-Channel Telemetry)

Plan for observers beyond network/logs:

- Storage snapshot/diff
- Permissions/appops snapshot
- Process/resource utilization
- Package state and foreground activity
- Event markers for step correlation

### 13.8 Evidence Packs + Provenance

Store tool versions, operator identity (host/user), and manifest hashes per
run. Consider signed manifests later; do not require them to start.

### 13.9 Post-Processing Pipeline

Separate extractors, feature builders, and report renderers. All analysis must
be replayable from stored artifacts.

### 13.10 Retention + Security Controls

Define retention policies, allow pinning paper-critical runs, and enable
encryption-at-rest where possible. Summaries must redact sensitive values.

## 14. Design Discussion Checklist (Before Coding)

Use this checklist to align stakeholders before implementation:

### 14.1 Run Identity & Evidence

- What fields are required in `RunContext` and `RunManifest` v1?
- How will artifact hashing be performed (when and by which module)?
- Where will evidence packs live (`output/` vs external volume)?

### 14.2 Orchestration & Lifecycle

- What counts as `success` vs `degraded` vs `failed`?
- Which observers are **required** for a run to be valid?
- How should operator prompts be surfaced (CLI vs UI)?

### 14.3 Device & Target Control

- Which device reset steps are mandatory for repeatability?
- How will target identity be verified (package/version/hash)?
- Do we support split APK installs in v1?

### 14.4 Network Capture & Isolation

- Will traffic be captured on-device or host-side?
- Do we require proxy routing in v1?
- What are the minimum network artifacts (pcap, DNS log, TLS metadata)?

### 14.5 Post-Processing & Redaction

- What is the minimum acceptable `summary.json` content?
- Which fields are redacted and where?
- How will summaries link back to raw evidence?

### 14.6 Persistence & Auditability

- Do we need a run ledger DB now or later?
- Which tables are required for auditability in v1?
- How will runs be resumed after a crash?
