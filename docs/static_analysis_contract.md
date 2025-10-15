# Static Analysis Pipeline Contract

This document captures the agreed-upon contracts, execution order, and
ownership boundaries for the Static Analysis pipeline and CLI. It reflects the
current v2 implementation that now ships a modular detector framework,
reproducibility bundles, and a correlation layer that synthesises composite
findings.

## 0. Cross-Cutting Rules

- **Timestamp format:** All rendered timestamps must use `M-D-YYYY h:mm AM/PM`
  (America/Chicago time zone). If the host lacks the required zone data, fall
  back to UTC and annotate the fallback zone label.
- **Determinism:** Outputs must have fixed wording and deterministic ordering (sort lists before rendering).
- **Safety:** Never render raw secret values—only evidence pointers and short hashes.
- **Badges:** Valid status badges are `[OK]`, `[INFO]`, `[WARN]`, `[FAIL]`, and `[skipped]`.
- **Timing:** Every section returns a `duration_sec` (float) and renders it with one decimal place.
- **Evidence limit:** Renderers must display no more than `N` evidence entries (default `2`), appending `(+N more)` when additional entries are omitted.
- **Reproducibility bundle:** Persist a manifest digest, network-security policy
  graph, and string-index summary under `metadata.repro_bundle` for each run.
  Detectors that diff state (e.g., correlation, split aggregation) must consume
  this bundle rather than reparsing raw files.

## 1. Core Types

The following data classes (under `scytaledroid/StaticAnalysis/core/`) define the shared interfaces:

### `DetectorContext`
Read-only input passed to each detector.
- `apk_path: str`
- `app_label: Optional[str]`
- `package_name: str`
- `version_name: str`
- `version_code: str | int`
- `manifest_tree / manifest_xml`
- `dex_index`
- `resources_index`
- `sdk_min`, `sdk_target`, `sdk_compile: int`
- `flags` (debuggable, allowBackup, usesCleartextTraffic, requestLegacyExternalStorage, networkSecurityConfig, sharedUserId, etc.)
- `permissions_declared: set[str]`
- `clock: Callable[[], str]` – returns formatted timestamp

### `EvidencePointer`
- `location: str` (e.g., `AndroidManifest.xml:/manifest/application/provider[1]`)
- `hash_short: str` (e.g., `#h:77d5…`, derived from snippet hash; snippet is not stored)

### `Finding`
- `id: str` (stable identifier, e.g., `STORAGE_PLAINTEXT_PREFS`)
- `title: str`
- `severity_gate: Literal["P0", "P1", "P2"]`
- `category_masvs: Literal["NETWORK", "PLATFORM", "STORAGE", "PRIVACY", "CRYPTO", "RESILIENCE"]`
- `status: Badge`
- `because: str` (concise causal chain)
- `evidence: list[EvidencePointer]`
- `remediate: str` (single prescriptive sentence)
- `metrics: dict`
- `tags: set[str]`

### `DetectorResult`
- `section_key: str`
- `status: Badge`
- `metrics: dict[str, int | float | str]`
- `evidence: list[EvidencePointer]`
- `notes: list[str]`
- `duration_sec: float`
- `subitems: Optional[list[dict]]`
- `raw_debug: Optional[str]`

## 2. Directory Layout

```
scytaledroid/StaticAnalysis/
  cli/
    menu.py             # interactive CLI menu
    options.py          # CLI flags (profile, verbosity, evidence limits)
    progress.py         # headers/footers for repo/group runs
  core/
    pipeline.py         # orchestrates detector execution
    detector_runner.py  # pipeline stage registry and orchestration helpers
    context.py          # DetectorContext builder and shared config
    findings.py         # DetectorResult, Finding, EvidencePointer models
    manifest_utils.py   # manifest parsing helpers
    models.py           # manifest/permission/component summaries
  detectors/
    integrity.py        # signing + identity baseline
    manifest.py         # manifest hygiene flags
    permissions.py      # Androguard-backed permission analytics
    components.py       # IPC exposure tables
    provider_acl.py     # content provider ACL review
    network.py          # network posture + NSC graphs
    domain_verification.py
    secrets.py
    storage.py
    dfir.py             # DFIR evidence hints
    webview.py
    crypto.py
    dynamic.py
    fileio.py
    interaction.py
    sdks.py
    native.py
    obfuscation.py
    correlation/        # diffing, scoring, detector shim
  modules/
    network_security/   # NSC parser + models
    string_analysis/    # string index builder + pattern catalog

scytaledroid/Reporting/
  … optional exporters (CLI renders sections directly)
```

All report generation responsibilities live under the root-level `scytaledroid/Reporting/` package so that Static Analysis code
focuses solely on producing normalized results. The CLI should hand off completed detector output to the reporting module for any
export or persistence workflow.

## 3. Detector Execution Order

`detector_runner.py` must invoke detectors in the following fixed order,
forwarding each `DetectorResult` to the renderer. Stages marked as
`include_in_quick=False` produce `[skipped]` results when the quick profile is
selected so report wording remains deterministic:

1. `IntegrityIdentityDetector`
2. `ManifestBaselineDetector`
3. `PermissionsProfileDetector`
4. `IpcExposureDetector`
5. `ProviderAclDetector`
6. `NetworkSurfaceDetector`
7. `DomainVerificationDetector`
8. `SecretsDetector`
9. `StorageBackupDetector`
10. `DfirHintsDetector`
11. `WebViewDetector` *(skipped in quick profile)*
12. `CryptoHygieneDetector` *(skipped in quick profile)*
13. `DynamicLoadingDetector` *(skipped in quick profile)*
14. `FileIoSinksDetector` *(skipped in quick profile)*
15. `UserInteractionRisksDetector` *(skipped in quick profile)*
16. `SdkInventoryDetector` *(skipped in quick profile)*
17. `NativeHardeningDetector` *(skipped in quick profile)*
18. `ObfuscationDetector` *(skipped in quick profile)*
19. `CorrelationDetector`

CLI renderers must respect this order when printing sections.

## 4. Detector Responsibilities and Contracts

Each detector owns a specific concern area and returns a `DetectorResult` meeting the cross-cutting rules.

- **integrity.py:** APK identity (hashes, size), signing schemes, certificate
  lineage, split awareness, and toolchain metadata. Status defaults to `[OK]`
  unless signing data is missing or parsing fails.
- **manifest.py:** Manifest hygiene flags (debuggable, allowBackup,
  usesCleartextTraffic, sharedUserId, foreground service types), feature and
  library inventory, and context notes. Status `[INFO]` with escalations when
  risky flags are enabled.
- **permissions:** Permission‑first analytics, DB‑aware protection mapping,
  capability grouping, and tunable risk scoring.
  - Analysis helpers:
    - `modules/permissions/analysis/capability_signal_classifier.py` — LOC/CAM/MIC/… signals
    - `modules/permissions/analysis/risk_scoring_engine.py` — risk score (3 decimals) + grade (A–F)
  - Renderers:
    - `modules/permissions/render_postcard.py` — postcard (Risk bar, Score/Grade, High‑signal, Footprint table)
    - `modules/permissions/render_summary.py` — Risk Summary (Abbr | Score | Grade | D | S | V)
    - `modules/permissions/render_matrix.py` — Signal & Permission matrices
  Status `[INFO]` with concise notes; secrets never printed.
- **components.py:** Export posture for activities, services, receivers, and
  shared UID partners, including exported intent filters and namespace overlap
  hints. Status `[WARN]` when unguarded exports exist.
- **provider_acl.py:** Provider ACL matrix (read/write permissions,
  grantUriPermissions, path permissions) and risk ratings. Status `[FAIL]` for
  sensitive authorities without guards; otherwise `[INFO]`/`[WARN]`.
- **network.py:** Network security policy graph normalisation, cleartext
  viability, pinning hints, endpoint differentials, and split-aware posture.
  Status `[WARN]` when cleartext or debug trust anchors leak into release
  builds.
- **domain_verification.py:** Auto-verify coverage, intent filter mismatches,
  digital-asset links hints. Status `[INFO]` by default.
- **secrets.py:** Contextual secret detections with hashed evidence pointers,
  suppression metrics, and coalesced roles. Status `[WARN]` when production
  secrets surface.
- **storage.py:** SharedPreferences/database/file hotspots, backup interaction
  risks, and sensitivity heatmaps. Status `[WARN]` when plaintext intersects
  with backup or shared storage.
- **dfir.py:** Predictive evidence hints (likely runtime file paths, logcat
  tags, registry traces) for follow-on triage. Status `[INFO]` with `[WARN]`
  escalations when sensitive data remains recoverable.
- **webview.py:** In-app browser posture, JavaScript interface hardening, file
  access, and mixed-content controls. Status `[WARN]` when powerful bridges or
  mixed content are enabled.
- **crypto.py:** Crypto API misuse graph (ECB, static IVs, weak digests,
  predictable random sources) with remediation snippets. Status `[WARN]` on weak
  constructs.
- **dynamic.py:** Dynamic loading, reflection, and DexClassLoader usage tied to
  dangerous permissions. Status `[WARN]` when exploitable pathways exist.
- **fileio.py:** External/world-readable write sinks, temp-file hygiene, and
  leftover artifact checks. Status `[WARN]` when sensitive payloads escape the
  app sandbox.
- **interaction.py:** Overlay/accessibility escalation surfaces, clipboard
  leakage, and pending-intent hygiene. Status `[WARN]` when paired with
  sensitive permissions.
- **sdks.py:** SDK/library inventory joined with permission posture and notes on
  outlier capabilities. Status `[INFO]`.
- **native.py:** Native library coverage, hardening flags (PIE, RELRO, NX,
  canary), and ABI support. `[INFO]` by default; `[WARN]` on missing hardening.
- **obfuscation.py:** Obfuscation depth, anti-analysis fingerprints, reflective
  spikes. `[INFO]`/`[WARN]` depending on aggressiveness.
- **correlation/`detector.py`:** Combines prior `DetectorResult`s into
  normalised P0/P1 `Finding` objects using deterministic rules:
  1. `P0_CLEARtext_VIABLE`: `usesCleartextTraffic` and ≥1 HTTP endpoint and `INTERNET` permission.
  2. `P0_DATA_EXFIL_IPC`: Dangerous permission (contacts/location) with unguarded exported component (activity/provider).
  3. `P0_HARDCODED_CRED_AT_RISK`: Sensitive secret type with matching endpoint family.
  4. `P1_BACKUP_EXTRACTABLE_SECRETS`: `allowBackup` with plaintext storage hit.
  5. `P1_WEAK_CRYPTO_SENSITIVE_FLOW`: AES-ECB or static IV CBC near token/password usage.
  6. `P1_DYNAMIC_LOADING_WITH_DANGEROUS_PERMS`: Dynamic class loading with dangerous permissions.
  7. `P1_PROVIDER_URI_GRANT_MISUSE`: Exported provider with `grantUriPermissions` but no read/write guards.

Findings must be sorted with all `P0` (alphabetical by title) followed by `P1` (alphabetical). No duplicates.

## 5. Rendering (`cli/sections.py`)

Each renderer accepts a `DetectorResult`, `verbosity`, and `max_evidence` and emits lines in the following order:

1. Section header (title).
2. Key metrics (compact).
3. Evidence list (respecting limit and `(+N more)` suffix).
4. Optional notes (one-liners).
5. `Timing: <X.Ys>`.
6. `Status: [BADGE]`.

On detector errors, render the header followed by `[skipped]` and the reason, then continue.

## 6. CLI Options (`cli/options.py`)

- `--profile {quick, full}`:
  - `quick`: executes stages 1–10 and the correlation detector. Later sections
    render as `[skipped]` with `skip_reason="skipped by quick profile"`.
  - `full`: runs the entire pipeline.
- `--verbosity {normal, detail, debug}`:
  - `detail`: increases evidence limit (e.g., from 2 to 5).
  - `debug`: appends `raw_debug` output after each section block.
- `--max-evidence N`: overrides default evidence display limit.
- Filters: `--only P0,P1` (show headers for others but skip details), `--group`, `--app` filters.

Presentation changes must not alter `Finding` content.

## 7. Rollups (`core/repository.py`, `cli/progress.py`)

- **Group Summary:**
  - Totals: apps, artifacts, P0/P1/P2 counts.
  - Top three risk titles (by frequency across apps).
  - Slowest artifact.
  - `Finished: <timestamp>`.
- **Repository Summary:**
  - Totals and status buckets (Failed = P0 present, Warn = P1 only, Info = P2 only).
  - Duration, `Started`, `Finished` timestamps.
  - Export hint for downstream tooling.

## 8. Implementation Sequence (Suggested)

1. Renderer scaffolding (`sections.py`, `section_utils.py`, `progress.py`, timestamp formatting).
2. Stage 0 detectors (Integrity, Components hygiene, Permissions).
3. IPC & Provider ACL detectors.
4. Network & Domain Verification detectors.
5. Secrets detector.
6. Storage, WebView, Crypto detectors.
7. Dynamic, File I/O, Interaction detectors.
8. SDKs, Native, Obfuscation detectors.
9. Correlation logic for P0/P1 findings.
10. Summaries, rollups, and CLI polish (`--profile`, `--only`, `--max-evidence`).

## 9. Acceptance Checklist

- Each section reports timing and status.
- No raw secrets are rendered.
- Evidence respects the max limit and displays `(+N more)` when truncated.
- Ordering and wording remain deterministic.
- Timestamp formatting is correct.
- Detectors fail gracefully with `[skipped]` and a one-line reason.

## 10. Example Output Snippets

- `Started: 10-7-2025 11:19 AM`
- `Timing: 0.7s`
- `Status: [WARN]`
- Evidence block:
  - `classes.dex:com/crypto/CipherUtil.java:73  #h:1ab3…`
  - `AndroidManifest.xml:/manifest/application/provider[1]  #h:9f20…`
  - `(+3 more)`

---

This contract is the source of truth for future implementations of the Static Analysis pipeline and its CLI rendering.
