# Dynamic Analysis Engine Buildout Plan

This document summarizes the core parts needed to build out ScytaleDroid's
dynamic analysis engine beyond the current scaffolding. It is intended as a
living checklist for implementation sequencing.

## 1. Run Lifecycle Core (existing, extend as needed)

- **Run context + manifest:** record run metadata, environment, target metadata,
  observers, artifacts, and outputs. (Done.)
- **Evidence pack layout:** deterministic evidence folder and manifest writer.
- **Run event log:** structured timeline of run activity (`notes/run_events.jsonl`).

## 2. Target Management (existing, expand)

- **Package metadata:** version, paths, and dumpsys snapshot.
- **Launch orchestration:** start app via `monkey` or activity-specific intent.
- **Stop + cleanup:** force-stop app and snapshot any end-of-run state.
- **Optional install/uninstall:** install APKs or reset to known build.

## 3. Environment Baselines (existing, expand)

- **Device metadata:** build fingerprint, model, SDK, emulator detection.
- **Baseline snapshots:** permissions before/after, network state, battery state.
- **Host metadata:** OS, Python version, operator identity.

## 4. Observers (existing, expand)

- **Network capture:** tcpdump capture, host-side parsing, flow summaries.
- **System logs:** logcat capture, filtered tags, log signal extraction.
- **Optional sensors:** file system diffing, clipboard, screenshots, keystore probes.

## 5. Scenario Execution (existing, expand)

- **Manual flows:** operator-driven scenario timer + notes.
- **Scripted flows:** planned automation steps (UIAutomator, Espresso, etc.).
- **Scenario validation:** ensure required app states were hit (permissions, screens).

## 6. Dynamic Plan + Probe Execution (existing, expand)

- **Plan ingestion:** load static-analysis-driven plans with suggested probes.
- **Probe registry:** map probes to implementation modules and dependencies.
- **Probe execution:** run probes before, during, or after scenario as required.
- **Probe results:** consistent schema with status, artifacts, and findings.

## 7. Post-Processing + Summaries (existing, expand)

- **Summary artifacts:** `analysis/summary.json` + `analysis/summary.md`.
- **Flags and indicators:** cleartext HTTP, TLS MITM, notable log signals.
- **Evidence cross-links:** references from summary to raw artifacts.

## 7.1 Telemetry windows + anomaly modeling (paper alignment)

- **Telemetry capture:** CPU, memory, thread, and network counters collected
  at stable intervals using non-root ADB interfaces.
- **Windowing:** fixed-length, optionally overlapping windows with timestamps,
  sampling rate, and window size recorded in metadata.
- **Feature extraction:** per-window statistics (mean/variance/deltas).
- **Models:** Isolation Forest + One-Class SVM with logged parameters.
- **Outputs:** anomaly scores per window + thresholds, stored in
  `analysis/telemetry_windows.json` and `analysis/anomaly_scores.json`.

## 8. Persistence + Indexing (future)

- **Database integration:** defer to background job, maintain offline-first flow.
- **Artifacts registry:** storage metadata for future retrieval.
- **Run search:** surface recent runs, tags, and outcomes in UI/API.

## 9. Validation & Testing

- **Unit tests:** target manager parsing, probe registry behavior, event logging.
- **Integration tests:** dry-run orchestration with mocked adb + observers.
- **Acceptance checks:** evidence pack layout + manifest integrity.
