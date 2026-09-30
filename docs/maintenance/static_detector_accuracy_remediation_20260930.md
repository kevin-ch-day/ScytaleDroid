# Static detector accuracy remediation — 2026-09-30

The frozen audit is `output/audit/static_detector_accuracy/20260930T155941Z/AUDIT_MATRIX.md`.
It fixes the 15 selected July 2026 builds and 1,377 historical finding rows as
evidence. This source change applies only to future analyses; it does not edit
those rows, publication exports, or the September full-run database records.

## Corrected for future scans

- Decode numeric Android permission protection levels using the base-type mask.
  APK-declared `0x00000002` now resolves to signature; unknown permissions stay
  unknown in IPC and provider ACL summaries. A provider's missing general
  permission no longer overrides explicit read and write guards in its
  effective-guard summary.
- Interpret HTTP literals against target-SDK cleartext defaults, the manifest
  flag when applicable, and Network Security Config base/domain settings.
  More specific domains take precedence. Missing target SDK or unreadable NSC
  resources now produce an explicit policy-unknown literal bucket instead of
  a viable HTTP count. A literal remains evidence of packaged text, not
  evidence that a request was sent.
- Decode Android binary XML Network Security Config resources as well as text
  XML, read the standard unprefixed attributes, and apply `includeSubdomains`
  to each domain entry independently. Malformed or wrong-root resources retain
  their raw hash but carry `parse_valid=false`, so a target-SDK default cannot
  silently replace an unreadable referenced policy. A harvested APK's compiled
  resource was read-only verified to yield three domain policies.
- Retain parsed pin sets and trust anchors when a stored NSC policy is
  rehydrated for prior-report correlation; pinning comparisons now see the
  structured policy preserved in the reproducibility bundle.
- Record backup enablement as a configuration observation. Backup inclusion,
  sensitive content, and device-specific behavior are not established by
  `allowBackup` alone. For target SDK 30+, classify
  `requestLegacyExternalStorage` as an informational legacy attribute because
  Android 11+ ignores it for those targets.
- In the additive publication v2 helper, identify component findings by
  finding ID, exclude unrelated summary findings with their own IDs, and keep
  absent and weak manifest guards as separate counts. The historical
  `exported_components_without_permission_guard` CSV field is a frozen v1
  mixed-grain measure; its value of 955 is not silently replaced.
- Update the correlation contract prose to match the executable detector.
- Treat exported components and providers with absent or broadly grantable
  manifest guards as `P2/INFO` review observations. Preserve their finding IDs
  for lineage and add `assessment_state=REVIEW_REQUIRED`. A URI-grant flag
  without a general permission no longer creates its own warning when
  directional ACLs exist. Manifest aggregate summaries exclude unresolved
  guards from the weak bucket and respect provider read/write permissions.
- Correlation priority method `correlation_priority_v2` excludes informational
  findings from finding weights and no longer adds fixed points solely for
  backup enablement or the legacy-storage attribute. It remains a synthetic
  triage score, not a calibrated probability or exploitability assessment.
- `scripts/publication/export_component_exposure_v2.py` reads the frozen cohort
  manifest and finding CSV without database access and writes a separate
  receipt-backed v2 export. On the exact 15-build/1,377-row July cohort, the
  derived counts are 1,114 distinct finding-represented exported components,
  928 with an absent manifest guard or provider guard direction, and 144
  historically labeled weak by the detector. The exact reviewed signature
  correction file identifies 31 of those 144 as false weak-guard labels;
  113 weak labels remain unadjudicated. These are exposure/review buckets,
  not vulnerability counts. The output is under
  `output/audit/static_detector_accuracy/20260930T155941Z/component_exposure_v2_source_patch/`.

## Still requiring a separate evidence and method change

1. Establish sensitive code behavior, runtime caller checks, URI-grant scope,
   and reachable data/action semantics before promoting exported IPC/provider
   observations to validated vulnerability claims. The current classifier
   stops at manifest access-control evidence.
2. Backup-rule XML (`dataExtractionRules`, `fullBackupContent`) and included
   sensitive files need path-level parsing. The informational backup finding
   does not assert that no data is exposed.
3. Cleartext policy remains a platform-stack approximation. Native/raw-socket
   behavior and device API variation may not honor the manifest/NSC policy in
   the same way; dynamic traffic evidence is a separate observation.
4. The frozen July metric generator still implements v1 title matching. The
   additive v2 CSV now gives explicit component identities and guard buckets,
   but a future publication dataset must preregister its analysis unit and
   reconcile component inventory independently before replacing any v1
   result. No frozen artifact is overwritten.
5. Raw detector rows overlap across IPC, provider ACL, manifest, and storage
   detectors. Report raw rows, distinct component identities, and distinct
   conditions separately. Precision and recall require an independently
   adjudicated positive and negative exact-build corpus; the audit packet is
   a review frame, not such a corpus.
