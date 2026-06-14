# ScytaleDroid External Schema Research Memo (2026-06-14)

This memo is an outside-context research pass for redesigning `scytaledroid_core_prod` into a stronger Android static/dynamic analysis research database without a greenfield rewrite.

This pass is design-only:

- no live DB changes
- no `ALTER TABLE`
- no row pruning
- no Permission Intel modifications

This memo should be read together with:

- [scytaledroid_canonical_schema_map_2026-06-14.md](./scytaledroid_canonical_schema_map_2026-06-14.md)
- `output/audit/canonical_schema_map/20260614T154650Z/summary.json`

## Executive Summary

The main lesson from the outside research is that ScytaleDroid should not be designed as a generic scan-results database. It should be designed as a **research-grade Android analysis evidence database** with clear boundaries between:

- identity
- execution
- evidence facts
- authority overlays
- provenance
- read models
- governance

The strongest repo-specific conclusions are:

1. `apps`, `app_versions`, and `apk_sets` are a good start for identity, but they are not yet enough to model modern Android delivery structure.
2. `artifact_registry` should remain a ledger, not become the canonical APK identity table.
3. static analysis in ScytaleDroid already has a decent execution spine and evidence spine, but several important evidence dimensions are still collapsed into blobs, summaries, or soft joins.
4. dynamic analysis in ScytaleDroid needs more first-class scenario and capture-context modeling than more generic “results” tables.
5. Permission Intel should remain external authority, but ScytaleDroid needs explicit snapshot/hash/version references to keep old analyses reproducible if the authority changes later.
6. MariaDB schema cleanup still matters, but only after the canonical data model is explicit.

The recommended target is not a rewrite into a graph database or a giant event log. It is a staged normalization of the current repo spine into:

- identity spine
- execution spine
- static evidence facts
- dynamic evidence facts
- authority overlay
- provenance/manifest layer
- read-model/export layer
- governance/audit layer

## What ScytaleDroid’s Database Should Be Able to Prove

As a serious Android static/dynamic analysis research platform, `scytaledroid_core_prod` should be able to prove:

1. **Identity**
   - Which package, version, signing identity, APK set, split set, and harvest source were analyzed.
2. **Execution**
   - Which static session/run or dynamic session/run produced the data, under which profile, scenario, device, tool version, and schema version.
3. **Evidence**
   - Which rows of evidence support a finding, posture surface, MASVS/MASTG mapping, permission claim, or network-behavior claim.
4. **Authority**
   - Which permission/governance/mapping authority inputs were applied at analysis time.
5. **Reproducibility**
   - Which manifests, hashes, receipts, and configuration values are needed to replay, audit, defend, or export the result later.
6. **Exportability**
   - Which data can be exported as operator dashboards, web read models, paper tables, or reproducibility bundles without redefining truth each time.

## Outside Research Findings and Repo-Specific Implications

### 1. Android app / package / artifact modeling

#### Outside research

Official Android guidance establishes that:

- Android App Bundles are the modern publishing format and defer device-specific APK generation and signing to distribution tooling and stores.
- The bundle format explicitly distinguishes modules and asset packs.
- `bundletool` is the underlying tool used to convert app bundles into deployable APK sets.
- Play Feature Delivery separates features into install-time, conditional, or on-demand modules.
- `PackageInfo` and `ApplicationInfo` expose installed app identity and state, including:
  - `packageName`
  - `versionName`
  - `getLongVersionCode()`
  - `baseRevisionCode`
  - `splitNames`
  - `splitRevisionCodes`
  - `signingInfo`
  - `minSdkVersion`
  - `targetSdkVersion`
  - install/update times
- `InstallSourceInfo` exposes how an app was installed and by whom.
- Android 11+ package visibility rules mean that on-device package observation is filtered by platform policy, especially for non-rooted workflows.

#### Repo-specific implication

Current ScytaleDroid identity tables:

- `apps`
- `app_versions`
- `apk_sets`
- `apk_set_members`
- `android_apk_repository`

are enough to express “we analyzed package/version/APK set”, but they are not yet enough to express **delivery structure** and **installed-state identity** with research-grade fidelity.

The research suggests ScytaleDroid should add additive canonical identity modeling for:

- `apk_artifacts`
  - one row per physical APK file
- `apk_splits`
  - split role, split name, split revision, config axis, module relationship
- `signing_certificates`
  - leaf certificate digest, certificate chain metadata, rotation lineage if available
- `apk_delivery_context`
  - base vs config vs feature split
  - install-time vs conditional vs on-demand delivery mode

Important missing columns for the current canonical spine:

- `app_versions.long_version_code`
- `app_versions.base_revision_code`
- `apk_set_members.split_name`
- `apk_set_members.split_role`
- `apk_set_members.split_revision_code`
- `apk_set_members.module_name`
- `apk_set_members.config_axis`
- `apk_set_members.delivery_mode`
- `android_apk_repository.signing_cert_sha256`
- `android_apk_repository.signing_scheme_version`
- `apps.install_source_package`
- `apps.first_install_time_utc`
- `apps.last_update_time_utc`
- `apps.target_sdk_version`
- `apps.min_sdk_version`

What should remain canonical versus derived:

- canonical:
  - package/version identity
  - APK file identity
  - split structure
  - signing identity
  - install source and install/update times when observed from a device
- derived:
  - risk or exposure summaries of split sets
  - “latest APK per package”
  - aggregate split-count dashboards

### 2. Static analysis evidence modeling

#### Outside research

OWASP MAS guidance and Android static-analysis research emphasize:

- MASTG is test-process oriented, not just severity oriented.
- MASVS is the verification/control model.
- MASWE provides weakness categories linking control expectations and concrete defects.
- static Android evidence often centers on:
  - manifest declarations
  - permissions
  - components
  - providers and authorities
  - exported surface
  - string and URL artifacts
  - network security configuration
  - code- and lifecycle-aware flow evidence
- FlowDroid shows the value of lifecycle-aware, source/sink-oriented static evidence.
- Stowaway/permission mapping research shows the value of explicit API-to-permission mappings and overprivilege reasoning.
- Androguard emphasizes first-class APK/DEX/XREF/code-graph analysis rather than only flat summaries.
- MobSF demonstrates the practical value of exposing permissions, manifest/components, certificates, URLs/domains, and findings in one report surface, but it also encourages monolithic report payloads that ScytaleDroid should avoid copying directly.

#### Repo-specific implication

ScytaleDroid’s current static evidence model is directionally correct:

- `static_analysis_findings`
- `static_permission_matrix`
- `static_string_summary`
- `static_string_samples`
- `static_fileproviders`
- `static_provider_acl`
- MASVS read models

But several static evidence facts should become more explicitly first-class:

- manifest component facts
  - activities
  - services
  - receivers
  - providers
  - exported state
  - permission gates
- network security configuration facts
  - cleartext policy
  - domain config overrides
  - trust anchors
  - pinning-relevant declarations
- detector evidence facts
  - detector id
  - detector/ruleset version
  - source location
  - evidence reference
  - confidence
  - limitation
  - mapping version

Recommended first-class static fact families:

- `static_manifest_component_facts`
- `static_manifest_permission_facts`
- `static_network_security_config_facts`
- `static_library_or_sdk_facts`
- `static_code_flow_facts` for high-value taint or source/sink outputs
- `static_detector_evidence_facts`

Blob/JSON versus scalar guidance:

- scalar first for:
  - package/component names
  - exported flags
  - protection levels
  - permission names
  - detector ids
  - file/class/method references
  - MASVS/MASTG/MASWE identifiers
  - confidence / limitation / severity / surface type
- JSON only for:
  - cold receipts
  - raw detector payload fragments
  - archival debug bundles

This is particularly important because the live audit already shows zero-signal JSON columns in `static_analysis_runs`.

### 3. Dynamic analysis evidence modeling

#### Outside research

Dynamic Android security research and mature tooling show several recurring themes:

- dynamic analysis is coverage-limited and context-sensitive
- scripted interaction matters
- device/emulator differences matter
- network telemetry, logs, runtime permissions, and execution state need explicit capture windows
- TaintDroid and later dynamic taint work show the value of explicit runtime evidence trails
- DroidScope shows the value of connecting high-level Android semantics to lower-level execution traces
- MobSF dynamic analysis emphasizes interactive instrumented testing and runtime/network capture, but its documented Android dynamic support is rooted Android 4.1–11 / API 30 oriented, which is a weaker fit for ScytaleDroid’s current physical-device, modern-Android posture
- OWASP MASTG dynamic testing emphasizes logs, runtime behavior, storage, IPC, TLS/network, and environment-aware testing rather than a single “dynamic risk score”

#### Repo-specific implication

Current ScytaleDroid dynamic canonical table:

- `dynamic_sessions`

Current canonical dynamic fact tables:

- `dynamic_telemetry_network`
- `dynamic_telemetry_process`

Current dynamic derived/secondary tables:

- `dynamic_network_features`
- `dynamic_network_indicators`

What `dynamic_sessions` should prove:

- which app/package/APK set was exercised
- on which device
- under which scenario/profile/stimulus
- during what capture window
- with what app state and environment
- with which runtime permissions and network context

The research strongly suggests ScytaleDroid needs additive canonical dynamic context tables:

- `dynamic_scenarios`
  - scenario id
  - human-readable scenario label
  - script/manual classification
  - intended behavioral targets
- `dynamic_capture_windows`
  - start/end timestamps
  - window label
  - capture modalities active during the window
- `dynamic_runtime_permission_state`
  - granted/denied state at runtime
  - before/after state if changed
- `dynamic_device_state_snapshots`
  - device model, Android version, rooting state, network/VPN/proxy state, screen state, battery/power state if relevant
- `dynamic_log_events`
  - structured logcat/event rows if they matter beyond flat artifact storage
- `dynamic_network_flows`
  - canonical flow records derived from PCAP or proxy telemetry
- `dynamic_interaction_steps`
  - scripted or operator-driven step sequence
- `dynamic_account_or_session_state`
  - anonymized login/account state markers

What context is currently missing or under-modeled:

- scenario identity
- explicit capture-window identity
- granted runtime permission state
- network environment state
- proxy/VPN/capture-tool state
- app foreground/background state
- interaction script / step coverage
- account/login state
- PCAP-to-row lineage

This is the difference between “we ran the app dynamically” and “we can defend what runtime conditions produced this evidence.”

### 4. Permission Intel interface

#### Outside research

The external guidance on authority integration is consistent:

- authority taxonomies evolve
- long-lived analytical stores need snapshot or version references
- upstream authority outputs should not silently rewrite the meaning of historical analyses
- provenance systems and SBOM/provenance standards all emphasize versioned descriptors, hashes, and immutable references to external inputs

#### Repo-specific implication

ScytaleDroid should not own or mutate Permission Intel. But ScytaleDroid should store explicit references to which authority snapshot was applied when the analysis was generated.

Recommended additive authority-reference fields:

- `permission_intel_snapshot_id`
- `permission_authority_hash`
- `permission_authority_version`
- `permission_mapping_generated_at_utc`
- `permission_source_catalog_name`
- `permission_source_schema_version`

Best candidate local tables for these references:

- `permission_audit_snapshots`
- `permission_signal_observations`
- `static_analysis_runs`
- potentially run-level or session-level provenance manifests

Why this matters:

- if Permission Intel changes later, old ScytaleDroid analyses remain reproducible
- exported papers and dashboards can state which authority snapshot they used
- disagreements between historical and current authority become explainable instead of silent

### 5. Research reproducibility and artifact provenance

#### Outside research

The reproducibility and provenance sources converge on several needs:

- artifact identity should be hash-addressable
- provenance should capture source, build or run process, environment, and outputs
- attestation and SBOM standards benefit from separating canonical metadata from derived documents
- ACM artifact review emphasizes that a serious result should be independently inspectable and rerunnable
- NIST SSDF emphasizes documented secure development and integrity-oriented practices
- SLSA provenance focuses on what produced an artifact, from what inputs, under what process
- GitHub artifact attestations show a practical provenance pattern: signed claims about who built what, from what workflow, producing which artifact
- SPDX and CycloneDX both show that a structured inventory/provenance object benefits from:
  - components
  - relationships
  - metadata
  - hashes
  - creator/tool information
  - evidence/pedigree

#### Repo-specific implication

ScytaleDroid should formalize a provenance/manifest layer rather than distributing the responsibility across ad hoc JSON files, report blobs, and receipts.

Recommended canonical manifest scopes:

- one manifest per `static_analysis_run`
- one manifest per `dynamic_session`
- one manifest per `apk_set`
- one manifest per `analysis export` or `paper cohort` when producing derived research outputs

Minimum manifest contents:

- canonical DB row IDs
- package/version/APK set identity
- relevant file hashes
- tool git commit
- tool semver
- schema version
- config hash
- detector/ruleset version hashes
- device snapshot reference
- authority overlay reference
- evidence artifact paths and digests
- export digest
- receipt references

This does not require making the manifest table the main truth surface. It should be a provenance cross-section over the canonical spine.

Recommended additive provenance tables:

- `analysis_run_manifests`
- `dynamic_session_manifests`
- `apk_set_manifests`
- `analysis_export_manifests`
- `manifest_artifact_links`

### 6. MariaDB schema design

#### Outside research

MariaDB guidance is directly relevant to ScytaleDroid’s current debt:

- FK columns and referenced columns must match type; integer size and sign must also match
- JSON is an alias of `LONGTEXT COLLATE utf8mb4_bin`; it is not a high-performance structured-document store
- generated columns are useful for deterministic derived values, not for replacing explicit canonical fields indiscriminately
- constraints are a valid way to enforce integrity, including `CHECK`
- `ALTER TABLE` support varies by operation and engine; migration phases should distinguish additive/in-place changes from heavier rebuild-style changes
- information schema surfaces are strong enough to support migration governance and preflight auditing

#### Repo-specific implication

Current dangerous or misleading schema patterns in ScytaleDroid:

- join-key collation drift across canonical tables
- signed/unsigned mismatch on dynamic-to-static linkage
- legacy string timestamps still coexisting with typed replacements
- zero-signal JSON/LONGTEXT columns in canonical execution tables
- legacy compatibility tables that still look deceptively “live”

Which columns are dangerous now:

- `dynamic_sessions.static_run_id`
- `static_analysis_runs.run_started_utc`
- `static_session_run_links.session_stamp`
- short child `session_stamp` columns in static evidence tables
- `artifact_registry.dynamic_run_id` when treated as canonical instead of compatibility

Which fields should remain JSON/LONGTEXT:

- receipts
- raw evidence payload snapshots
- archival manifests
- export bundles

Which hot JSON/text fields should become scalar or child rows:

- detector/ruleset evidence on `static_analysis_runs`
- any frequently-filtered dynamic environment details
- permission authority version/hash references
- capture-window and interaction-step data

Which tables should intentionally stay FK-loose:

- `artifact_registry`
- `schema_migrations`
- `analysis_derivation_receipts`
- prune/audit/log tables
- other ledger surfaces preserving detached historical evidence

### 7. External tool comparison

#### MobSF

MobSF’s strengths:

- integrated static + dynamic platform
- easy operator reporting
- broad scan coverage
- REST API oriented

MobSF ideas worth borrowing:

- clear separation between static analyzer and dynamic analyzer concerns
- easy export/reporting surfaces
- explicit runtime/network evidence surfacing

MobSF ideas to avoid copying directly:

- monolithic report-blob mentality
- dynamic assumptions tied to rooted/older Android support as the main model

ScytaleDroid advantage over MobSF:

- MariaDB-backed lineage
- explicit session modeling
- stronger room for provenance and research exports
- stronger fit for real-device and evidence-pack workflows

#### Androguard

Androguard’s strengths:

- APK/DEX/XREF/code-graph orientation
- bulk-analysis posture
- library/toolkit style integration

Ideas worth borrowing:

- first-class code/XREF evidence where useful
- explicit multidex or multi-artifact relationships
- bulk-analysis provenance at the session level

What not to copy:

- low-structure “just store whatever the library emits” persistence

#### Frida / Objection style workflows

These workflows are:

- interactive
- script-heavy
- session-driven
- evidence rich but often not strongly normalized

Schema implication:

- Frida-like evidence belongs in dynamic scenario / script / capture-window / evidence tables
- it should not reshape the identity spine

## Repo-Specific Recommendations

### What ScytaleDroid should change

- strengthen package/APK/split/signing identity modeling
- add explicit dynamic scenario and capture-window modeling
- add authority snapshot/hash/version references for Permission Intel overlays
- add provenance manifest tables tied to runs, sessions, APK sets, and exports
- convert repeated evidence-bearing JSON debt into child fact tables where filters and joins matter
- continue staged typed-column cutover and join-key normalization

### What ScytaleDroid should not change

- do not turn `artifact_registry` into the canonical identity table
- do not move Permission Intel logic into ScytaleDroid’s core DB
- do not make views the canonical source of truth
- do not harden FKs on ledger tables that need detached historical retention
- do not replace `static_analysis_sessions`, `static_analysis_runs`, and `dynamic_sessions` with a brand-new execution model

### What data is missing

- explicit APK artifact and split-delivery structure
- signing certificate and signing-scheme identity
- install-source metadata
- dynamic scenario identity
- capture-window identity
- runtime permission state
- network environment state
- interaction-step coverage
- authority snapshot/version/hash references
- run/session/export provenance manifests

### What columns are misleading or zero-signal

Live repo-specific zero-signal examples from the schema map:

- `artifact_registry.meta_json`
- `static_analysis_runs.detector_metrics`
- `static_analysis_runs.repro_bundle`
- `static_analysis_runs.analysis_matrices`
- `static_analysis_runs.analysis_indicators`

Misleading compatibility columns:

- `dynamic_sessions.static_run_id`
- `artifact_registry.dynamic_run_id`
- `static_analysis_runs.run_started_utc`

### What tables are canonical

Use the canonical classification from the schema map:

- identity spine tables
- execution spine tables
- first-class evidence tables
- local authority overlay tables

### What tables are derived / read-models

- `analysis_*`
- `risk_scores`
- `static_permission_risk_vnext`
- `static_findings_summary`
- `static_session_rollups`
- all `v_*` and `vw_*`
- `web_static_dynamic_app_summary_cache`

### What tables are ledgers / audit

- `artifact_registry`
- `schema_migrations`
- `schema_version`
- `analysis_derivation_receipts`
- `db_ops_log`
- prune/receipt-oriented tables

### What tables or columns should be deprecated

Legacy compatibility tables:

- `runs`
- `metrics`
- `findings`
- `buckets`
- `contributors`
- `static_findings`

Columns for retirement planning:

- `dynamic_sessions.static_run_id`
- `artifact_registry.dynamic_run_id`
- `static_analysis_runs.run_started_utc`
- zero-signal JSON columns listed above

## Proposed Target Schema Architecture

### Identity spine

- `apps`
- `app_versions`
- `apk_sets`
- `apk_set_members`
- new additive identity tables for:
  - `apk_artifacts`
  - `apk_splits`
  - `signing_certificates`
  - `apk_delivery_context`

### Execution spine

- `static_analysis_sessions`
- `static_analysis_runs`
- `dynamic_sessions`
- `static_session_run_links`
- additive:
  - `dynamic_scenarios`
  - `dynamic_capture_windows`
  - `dynamic_device_state_snapshots`

### Static evidence facts

- keep:
  - `static_analysis_findings`
  - `static_permission_matrix`
  - `static_string_summary`
  - `static_string_samples`
  - `static_fileproviders`
  - `static_provider_acl`
- add over time:
  - `static_manifest_component_facts`
  - `static_network_security_config_facts`
  - `static_detector_evidence_facts`
  - `static_library_or_sdk_facts`

### Dynamic evidence facts

- keep:
  - `dynamic_telemetry_network`
  - `dynamic_telemetry_process`
- add:
  - `dynamic_network_flows`
  - `dynamic_log_events`
  - `dynamic_runtime_permission_state`
  - `dynamic_interaction_steps`
  - `dynamic_account_or_session_state`

### Permission Intel authority overlay

- keep local overlay tables in ScytaleDroid
- add snapshot/hash/version references
- continue treating Permission Intel as external authority

### Provenance / manifest layer

- `analysis_run_manifests`
- `dynamic_session_manifests`
- `apk_set_manifests`
- `analysis_export_manifests`
- `manifest_artifact_links`

### Research / export / read-model layer

- current `v_*` and `vw_*`
- `analysis_*`
- web-facing summary tables/views
- export-specific cohort/materialization views

### Governance / audit layer

- `schema_migrations`
- `schema_version`
- `artifact_registry`
- `analysis_derivation_receipts`
- DB/log/receipt/report scripts and their outputs

## Staged Migration Roadmap

### Phase B1: collation and width normalization

Why it matters:

- canonical join keys currently drift across collations and widths

Likely tables / columns:

- `session_stamp` family across static execution/evidence tables
- `package_name` family across identity and collection tables
- `profile_key` family across taxonomy and execution tables

Preflight SQL:

- reuse `report_canonical_schema_map.py`
- reuse `report_type_normalization_preflight.py`
- compare row counts and join parity in session views

Risks:

- child-table drift may break read-model joins if done inconsistently

Rollback:

- staged rehearsals on clone
- view parity checks before production cutover

Tests:

- static session view contracts
- runtime run detail/index
- grain integrity and rollout tests

Touches runtime writers:

- indirectly, if writer assumptions about field width or collation exist

Touches live DB:

- yes, in a future migration pass

### Phase B2: typed-column read cutover

Why it matters:

- typed replacements are already populated

Likely tables / columns:

- `artifact_registry.dynamic_run_uuid`
- `dynamic_sessions.static_run_id_u`
- `static_analysis_runs.run_started_at_utc`

Preflight SQL:

- typed-read parity report

Risks:

- lingering consumers that still rely on legacy columns directly

Rollback:

- keep dual-write during parity window

Tests:

- parity tests
- runtime/read-model tests
- health and rollout diagnostics

Touches runtime writers:

- yes, but mainly to keep dual-write until retirement

Touches live DB:

- no structural DB change required for read cutover itself

### Phase B3: selective FK hardening

Why it matters:

- canonical source relationships should become enforceable

Likely tables / columns:

- `static_analysis_runs.static_session_id`
- `static_analysis_runs.app_version_id`
- `static_analysis_runs.apk_set_id`
- `dynamic_sessions.static_run_id_u`
- selected evidence-to-run foreign keys

Preflight SQL:

- orphan detection for each FK candidate
- sign/type/collation compatibility checks

Risks:

- runtime insert order and historical orphan debt

Rollback:

- one FK family at a time
- no ledger FK hardening in this phase

Tests:

- persistence tests
- session integrity
- dynamic/static linkage audits

Touches runtime writers:

- yes

Touches live DB:

- yes

### Phase B4: evidence / provenance manifest upgrades

Why it matters:

- reproducibility currently spans receipts, artifacts, and summaries without a unified manifest contract

Likely tables / columns:

- new manifest tables and manifest-to-artifact links
- authority snapshot/hash/version references

Preflight SQL:

- inventory of run/session/export artifacts and missing digests

Risks:

- overfitting manifest shape too early

Rollback:

- additive only

Tests:

- manifest writer tests
- export integrity checks
- provenance completeness audits

Touches runtime writers:

- yes, additive

Touches live DB:

- yes, additive only

### Phase B5: split APK / delivery modeling

Why it matters:

- modern Android distribution is module and split aware

Likely tables / columns:

- additive APK artifact / split / signing tables
- additive columns on `apk_set_members` and `android_apk_repository`

Preflight SQL:

- inspect current split-name and path conventions
- confirm source data availability from harvested APK metadata and on-device package info

Risks:

- partial historical backfill

Rollback:

- additive only

Tests:

- harvest inventory tests
- static run setup / APK library tests

Touches runtime writers:

- yes

Touches live DB:

- yes, additive only

### Phase B6: detector / MASVS / MASTG coverage matrix

Why it matters:

- ScytaleDroid needs better evidence-to-control/test mapping, not just summary views

Likely tables / columns:

- detector evidence facts
- MASVS/MASTG/MASWE mapping/version tables or additive columns

Preflight SQL:

- current mapping coverage, missing detector ids, missing evidence refs

Risks:

- semantic churn if scoring/model terminology is not stabilized first

Rollback:

- additive only

Tests:

- run-health / reporting wording tests
- MASVS view contracts

Touches runtime writers:

- yes

Touches live DB:

- yes, additive only

### Phase B7: read-model / view rebuilds

Why it matters:

- current views encode compatibility workarounds that should disappear after canonical cleanup

Likely surfaces:

- `v_run_identity`
- `v_static_handoff_v1`
- `v_static_session_health_v2`
- `v_web_runtime_run_*`
- `v_web_app_*`
- `vw_*`

Preflight SQL:

- count parity and sample-row parity before/after

Risks:

- web/operator regressions if rebuilt too early

Rollback:

- repo-owned DDL only

Tests:

- existing DB/read-model test slices

Touches runtime writers:

- indirect

Touches live DB:

- yes, view rebuild only

### Phase B8: deprecation / removal of legacy zero-signal columns

Why it matters:

- reduces ambiguity about truth surfaces

Likely surfaces:

- legacy tables
- legacy linkage/timestamp columns
- zero-signal JSON columns

Preflight SQL:

- prove no active writer/reader dependency
- prove parity against typed or canonical replacements

Risks:

- hidden consumer dependency

Rollback:

- deprecate first, remove later

Tests:

- persistence, reporting, artifact integrity, and historical audit tests

Touches runtime writers:

- yes, in final retirement phase

Touches live DB:

- yes, but only in a later controlled cleanup pass

## Annotated Bibliography

Accessed: 2026-06-14 unless otherwise noted.

### Android platform and packaging

1. **About Android App Bundles**  
   URL: https://developer.android.com/guide/app-bundle  
   Type: official docs  
   Why it matters: defines AAB as the publishing format and explains APK generation/signing deferral.  
   Schema implication: ScytaleDroid should distinguish publishing artifact identity from installed APK artifact identity.

2. **The Android App Bundle format**  
   URL: https://developer.android.com/guide/app-bundle/app-bundle-format  
   Type: official docs  
   Why it matters: documents bundle modules, asset packs, and bundle structure.  
   Schema implication: add explicit delivery/module/split modeling rather than treating every APK file as flat inventory.

3. **bundletool**  
   URL: https://developer.android.com/tools/bundletool  
   Type: official docs  
   Why it matters: bundletool is the authoritative AAB-to-APK-set generator.  
   Schema implication: preserve APK-set generation structure and bundletool-relevant split metadata.

4. **Overview of Play Feature Delivery**  
   URL: https://developer.android.com/guide/playcore/feature-delivery  
   Type: official docs  
   Why it matters: explains install-time, conditional, and on-demand feature delivery.  
   Schema implication: store delivery mode and module role for split artifacts.

5. **Build multiple APKs**  
   URL: https://developer.android.com/build/configure-apk-splits  
   Type: official docs  
   Why it matters: reinforces configuration-based APK splitting behavior and AAB-first distribution.  
   Schema implication: ScytaleDroid should treat base/config/feature splits as first-class artifact facts.

6. **PackageInfo API reference**  
   URL: https://developer.android.com/reference/android/content/pm/PackageInfo  
   Type: official docs  
   Why it matters: exposes split names, split revision codes, version information, signing info, install/update times.  
   Schema implication: add additive fields for installed-state artifact identity and versioning.

7. **ApplicationInfo API reference**  
   URL: https://developer.android.com/reference/android/content/pm/ApplicationInfo  
   Type: official docs  
   Why it matters: exposes `minSdkVersion`, `targetSdkVersion`, storage/source paths, and app-level install/runtime metadata.  
   Schema implication: canonical app identity should include min/target SDK and install-state snapshot values.

8. **InstallSourceInfo API reference**  
   URL: https://developer.android.com/reference/android/content/pm/InstallSourceInfo  
   Type: official docs  
   Why it matters: captures how an app was installed and the initiating package.  
   Schema implication: install source should be explicit in the identity or collection spine.

9. **Sign your app**  
   URL: https://developer.android.com/studio/publish/app-signing  
   Type: official docs  
   Why it matters: Play App Signing and certificate material are part of release identity.  
   Schema implication: store signing certificate digest, signing authority context, and rotation-aware identity.

10. **SigningInfo API reference**  
    URL: https://developer.android.com/reference/android/content/pm/SigningInfo  
    Type: official docs  
    Why it matters: exposes certificate history, multiple signers, and signing scheme version.  
    Schema implication: signing identity deserves additive canonical modeling.

11. **Package visibility filtering on Android**  
    URL: https://developer.android.com/training/package-visibility  
    Type: official docs  
    Why it matters: installed-app visibility is platform filtered on Android 11+.  
    Schema implication: inventory rows should record visibility posture and collection limitations, especially on non-root devices.

12. **Behavior changes: Apps targeting Android 15 or higher**  
    URL: https://developer.android.com/about/versions/15/behavior-changes-15  
    Type: official docs  
    Why it matters: target SDK changes alter runtime behavior and analysis meaning.  
    Schema implication: target SDK should be a first-class analysis context field.

13. **Network security configuration**  
    URL: https://developer.android.com/privacy-and-security/security-config  
    Type: official docs  
    Why it matters: network policy is declarative and analyzable from app artifacts.  
    Schema implication: add first-class network-security-config fact modeling.

### Security frameworks and Android analysis

14. **OWASP MASTG**  
    URL: https://mas.owasp.org/MASTG/  
    Type: framework / official docs  
    Why it matters: defines mobile testing processes, evidence areas, and technique vocabulary.  
    Schema implication: detector evidence should retain test/evidence lineage, not only severity.

15. **OWASP MASVS**  
    URL: https://mas.owasp.org/MASVS/  
    Type: framework / official docs  
    Why it matters: defines the control/verification model for mobile apps.  
    Schema implication: coverage matrices should map evidence to stable control identifiers.

16. **OWASP Mobile Application Security project**  
    URL: https://owasp.org/www-project-mobile-app-security/  
    Type: framework  
    Why it matters: explains the MASVS/MASTG/MASWE relationship.  
    Schema implication: ScytaleDroid should preserve control/test/weakness mappings explicitly.

17. **FlowDroid: precise context, flow, field, object-sensitive and lifecycle-aware taint analysis for Android apps**  
    URL: https://dl.acm.org/doi/10.1145/2594291.2594299  
    Type: paper  
    Why it matters: demonstrates the value of lifecycle-aware static evidence and source/sink precision.  
    Schema implication: high-value code-flow evidence should be stored as first-class rows, not only flattened findings.

18. **Android permissions demystified**  
    URL: https://dl.acm.org/doi/10.1145/2046707.2046779  
    Type: paper  
    Why it matters: permission/API mapping and overprivilege remain foundational to Android analysis.  
    Schema implication: permission evidence should retain mapping provenance and overprivilege semantics.

19. **TaintDroid: An Information-Flow Tracking System for Realtime Privacy Monitoring on Smartphones**  
    URL: https://www.usenix.org/legacy/event/osdi10/tech/full_papers/Enck.pdf  
    Type: paper  
    Why it matters: canonical example of runtime privacy/data-flow evidence on Android.  
    Schema implication: dynamic evidence schema should allow source/sink/runtime propagation records, not only summary features.

20. **DroidScope: Seamlessly Reconstructing the OS and Dalvik Semantic Views for Dynamic Android Malware Analysis**  
    URL: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/yan  
    Type: paper  
    Why it matters: shows the value of linking OS-level and app-level runtime semantics.  
    Schema implication: dynamic event modeling should retain layered provenance across app/runtime/system evidence.

### Tooling

21. **MobSF GitHub repository / docs overview**  
    URL: https://github.com/MobSF/Mobile-Security-Framework-MobSF  
    Type: tool docs  
    Why it matters: baseline static/dynamic mobile security workflow platform.  
    Schema implication: ScytaleDroid can borrow export/report ergonomics but should avoid monolithic report-only persistence.

22. **MobSF dynamic analysis docs (develop.md / docker docs)**  
    URL: https://github.com/MobSF/docs/blob/master/develop.md  
    URL: https://github.com/MobSF/docs/blob/master/running_mobsf_docker.md  
    Type: tool docs  
    Why it matters: documents dynamic-analysis environment assumptions, including rooted Android 4.1–11 / API 30 support.  
    Schema implication: ScytaleDroid’s physical-device, modern Android posture is a differentiator and needs stronger device-state provenance.

23. **Androguard documentation**  
    URL: https://androguard.readthedocs.io/en/latest/  
    Type: tool docs  
    Why it matters: APK/DEX/XREF/code-graph oriented analysis model.  
    Schema implication: if ScytaleDroid expands code-flow evidence, it should store typed code/XREF facts rather than only summaries.

24. **Androguard Bulk Analysis**  
    URL: https://androguard.readthedocs.io/en/latest/intro/bulk.html  
    Type: tool docs  
    Why it matters: emphasizes large-scale APK analysis and storing outputs elsewhere.  
    Schema implication: ScytaleDroid’s DB should preserve batch/session lineage explicitly.

25. **Androguard XREFs**  
    URL: https://androguard.readthedocs.io/en/latest/intro/xrefs.html  
    Type: tool docs  
    Why it matters: shows the importance of cross-reference graphs for code analysis.  
    Schema implication: code-evidence expansion should model references as facts, not opaque blobs.

### Provenance, reproducibility, and software supply chain

26. **Secure Software Development Framework (SSDF) Version 1.1**  
    URL: https://csrc.nist.gov/pubs/sp/800/218/final  
    Type: standard / official docs  
    Why it matters: secure-development and integrity-oriented practices framework.  
    Schema implication: migration governance, provenance manifests, and integrity audits should be first-class operational features.

27. **Secure Software Development Framework project page**  
    URL: https://csrc.nist.gov/projects/ssdf  
    Type: official docs  
    Why it matters: keeps SSDF framing current and connects related guidance.  
    Schema implication: provenance and audit should be ongoing, not one-off export logic.

28. **SLSA Build Provenance v1.2**  
    URL: https://slsa.dev/spec/v1.2/build-provenance  
    Type: standard  
    Why it matters: defines structured provenance about how artifacts were produced.  
    Schema implication: run/session/export manifests should capture inputs, process, and outputs in structured form.

29. **GitHub artifact attestations overview**  
    URL: https://docs.github.com/en/actions/concepts/security/artifact-attestations  
    Type: official docs  
    Why it matters: practical provenance pattern with signed claims about build origin and process.  
    Schema implication: ScytaleDroid receipts/manifests should support verifiable provenance-style exports.

30. **Using artifact attestations to establish provenance for builds**  
    URL: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds  
    Type: official docs  
    Why it matters: concrete operational guidance for provenance capture.  
    Schema implication: export manifests should include workflow-like producer metadata, digests, and artifacts.

31. **SPDX specification overview / specification pages**  
    URL: https://spdx.dev/about/overview/  
    URL: https://spdx.dev/use/specifications/  
    Type: standard  
    Why it matters: structured component/provenance metadata model.  
    Schema implication: component identity and manifest/export metadata should use stable IDs, hashes, relationships, and creator metadata.

32. **CycloneDX specification overview**  
    URL: https://cyclonedx.org/specification/overview/  
    Type: standard  
    Why it matters: rich BOM/provenance representation including components and pedigree.  
    Schema implication: ScytaleDroid export/manifests can borrow BOM-style structure for APK sets, evidence artifacts, and relationships.

33. **NIST SBOM guidance page**  
    URL: https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-supply-chain-security-guidance-20  
    Type: official guidance  
    Why it matters: highlights SPDX/CycloneDX/SWID as machine-ingestible structured metadata formats.  
    Schema implication: ScytaleDroid should keep export and provenance layers machine-readable and standards-aligned where practical.

34. **ACM Artifact Review and Badging**  
    URL: https://reviewers.acm.org/training-course/artifact-review-and-badging  
    Type: research-policy guidance  
    Why it matters: frames reproducibility as an expectation for serious experimental artifacts.  
    Schema implication: ScytaleDroid should preserve enough provenance to support independent audit, rerun, and result defense.

## Final Recommendation

The redesign target should be:

- not a greenfield evidence graph
- not just “fix collations and add FKs”
- not a report-blob archive

It should be a **staged normalization of the current ScytaleDroid spine into a reproducible Android analysis evidence database**.

The best next work remains:

1. use the canonical schema map as the control document
2. start with Phase B1 only
3. delay broader evidence-table additions until the canonical join keys and typed-read contract are stable
4. treat provenance/manifest upgrades as a first-class phase, not an afterthought
5. keep Permission Intel external, but make authority snapshotting explicit
