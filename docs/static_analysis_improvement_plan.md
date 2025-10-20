# Static analysis pipeline improvements and follow-up plan

## Implemented enhancements

- **Manifest hygiene coverage** – revived the `manifest_baseline` detector to audit
  release flags, task affinities, custom processes, and custom permission
  definitions. Findings now call out `android:debuggable`, cleartext traffic,
  auto-backup, scoped storage bypasses, weak custom permissions, stale
  `targetSdkVersion`, and other hygiene issues while emitting structured metrics
  (component counts, affinity maps, permission buckets) for downstream trend
  analysis.
- **Permission strength awareness** – enriched IPC exposure analysis with
  protection-level context for both framework and custom permissions.
  Exported components guarded by normal/dangerous permissions now trigger
  warnings, and metrics include guard-strength tallies to highlight recurring
  weaknesses.
- **Reproducibility bundle expansion** – the bundle now captures detector
  metrics for every stage, additional manifest context, classified custom
  permissions, and a richer string index snapshot with top hosts, origin
  counts, and secret-keyword hints. The diff basis mirrors these additions so
  drift detection can spot permission changes, SDK upgrades, or shifting string
  surfaces.
- **Baseline selection accuracy** – report differencing prefers prior scans from
  the same version code/name and gracefully falls back to the newest compatible
  artefact, preventing mismatched comparisons when hashes collide across
  releases.
- **Persistence scaffolding** – baseline ingestion now records detector metrics,
  reproducibility bundles, and normalized findings into relational tables when
  available, enabling external systems to query trend data without relying on
  JSON blobs.
- **Analytics matrices and workload profiling** – detector outputs now feed the
  analytics package, which emits severity/category matrices, guard-strength
  heatmaps, novelty indicators, and detector load classifications. The CLI
  surfaces these highlights and canonical persistence stores the JSON payloads
  for longitudinal research.

## Follow-up roadmap

1. **Historical analytics and dashboards** – surface baseline trends (e.g.,
   weak custom permissions, rising secret-keyword hits, recurring custom
   processes) via SQL views and lightweight dashboards once the new relational
   tables accumulate data. This provides analysts with immediate signal on
   risky apps or releases.
2. **Detector calibration loop** – feed stored detector metrics back into risk
   scoring and correlation so weightings can adapt to real-world findings.
   Persisted guard-strength counts and string host deltas open the door for
   machine-assisted prioritization.
3. **String intelligence enrichment** – layer bucketed string analytics (API
   key providers, cloud storage hints, analytics identifiers) into the
   reproducibility bundle so external tooling can cluster across apps. Leverage
   the existing `engine.strings` sampling logic to keep the snapshot consistent
   with the detector output.
4. **Release lineage awareness** – extend baseline selection with semantic
   version ordering and channel metadata (alpha/beta/release) to avoid noisy
   comparisons during staged rollouts. Persist channel hints alongside
   `static_analysis_runs` to support this logic.
5. **Detector attribution in persistence** – augment finding persistence with a
   `detector_id` column sourced from the parent `DetectorResult` so historical
   queries can filter by detector family (e.g., only manifest issues or network
   drifts).
6. **Automated regression suite** – add integration tests that execute the
   pipeline against curated APK fixtures, asserting manifest findings, string
   summaries, and persistence artifacts. This will prevent regressions as the
   pipeline grows.

These steps continue the trajectory toward richer, queryable intelligence and
less manual triage noise while keeping the pipeline cost-effective.
