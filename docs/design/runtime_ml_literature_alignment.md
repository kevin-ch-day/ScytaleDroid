# Runtime ML Literature Alignment

This note maps current runtime-network ML and Android static-analysis literature
to ScytaleDroid design choices. It is a design and reporting aid; it is not a
new evidence source and does not change collection, scoring, or DB state.

## Sources Reviewed

- Holland et al., "Towards Reproducible Network Traffic Analysis", arXiv 2022:
  https://arxiv.org/abs/2203.12410
- Li et al., "FOAP: Fine-Grained Open-World Android App Fingerprinting",
  USENIX Security 2022:
  https://www.usenix.org/conference/usenixsecurity22/presentation/li-jianfeng
- Ren et al., "ReCon: Revealing and Controlling PII Leaks in Mobile Network
  Traffic", MobiSys 2016 / arXiv:
  https://arxiv.org/abs/1507.00255
- Chen et al., "Drift-oriented Self-evolving Encrypted Traffic Application
  Classification for Actual Network Environment", arXiv 2025:
  https://arxiv.org/abs/2501.04246
- Aceto et al., "MIRAGE: Mobile-app Traffic Capture and Ground-truth
  Creation", IEEE 2019:
  https://ieeexplore.ieee.org/document/8888137/
- Jimenez-Berenguel et al., "PARROT: Portable Android Reproducible traffic
  Observation Tool", arXiv 2025:
  https://arxiv.org/abs/2509.09537
- scikit-learn IsolationForest and outlier-detection documentation:
  https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
  and https://scikit-learn.org/stable/modules/outlier_detection.html
- OWASP MASVS:
  https://mas.owasp.org/MASVS/
- Android Developers, `android:exported` security guidance:
  https://developer.android.com/privacy-and-security/risks/android-exported
- W3C PROV overview:
  https://www.w3.org/TR/prov-overview/

## Design Implications

### Runtime network behavior is useful even when traffic is encrypted

FOAP shows that encrypted Android traffic can still expose app and activity
signals through traffic structure. ReCon shows that network traffic can reveal
privacy-relevant leakage without requiring root or custom OS support. For
ScytaleDroid this supports keeping packet/window metadata, DNS/domain features,
PCAP provenance, and activity labels as first-class reporting inputs.

ScytaleDroid should avoid claiming decrypted-content visibility when it does not
have it. The stronger claim is that runtime metadata and endpoint behavior are
observable and can complement static risk posture.

### Reproducibility requires metadata and provenance, not just PCAPs

The pcapML work identifies lack of standardization as a reproducibility barrier
in network traffic analysis and proposes encoding metadata with raw captures.
MIRAGE and PARROT make the same point from the mobile-app side: reproducible
capture architecture, labeled captures, and current datasets are core parts of
mobile app traffic research. W3C PROV similarly frames provenance as information
about entities, activities, and people involved in producing data, including
support for reproducibility, versioning, and derivation.

For ScytaleDroid this validates:

- preserving run IDs, package names, version codes, APK hashes, static run IDs,
  dynamic run IDs, PCAP paths, activity labels, and capture windows;
- writing freeze/snapshot manifests instead of treating loose PCAP directories
  as sufficient;
- failing or warning when identity, lineage, or evidence roots are ambiguous;
- keeping `data/evidence/dynamic` as the evidence root and treating
  `output/` as derived reporting space.

### App churn is feature drift, not only collection inconvenience

Recent encrypted-traffic classification work explicitly links application
updates, function changes, and version changes to feature concept drift. That
matches the observed ScytaleDroid queue behavior where installed app builds can
change faster than a full cohort can be completed.

For reporting, the defensible model is:

- freeze or snapshot the evidence basis;
- report build/version-backed bundles;
- keep app-update churn as a limitation and operational status field;
- avoid treating every post-cutoff app update as evidence loss;
- surface duplicate build observations and thin baselines as lint warnings.

### Isolation Forest should remain the primary operational anomaly score

scikit-learn documents Isolation Forest as isolating observations by random
feature/value splits, where shorter average paths indicate more likely
anomalies. It also documents `random_state` as the reproducibility control.

For ScytaleDroid this supports:

- deterministic seeds in publication or freeze modes;
- keeping feature preprocessing fixed and recorded;
- treating contamination/thresholds as part of the output contract;
- recording model parameters in generated bundles.

### One-Class SVM is useful as a secondary check, not the sole gate

scikit-learn documents One-Class SVM as a novelty detector, but its outlier
detection guide warns that it is sensitive to outliers and needs careful
`nu` tuning. That supports ScytaleDroid's current direction: use OCSVM for
secondary interpretation or robustness checks, and warn when fallback training
or thin baselines weaken the score.

### Static posture should be reported as attack surface, not as dynamic proof

OWASP MASVS groups mobile risk into storage, crypto, authentication, network,
platform interaction, code quality, resilience, and privacy. Android's
`android:exported` guidance explains that exported components can be launched by
other apps and that ambiguous defaults can expose internal components.

For ScytaleDroid this supports:

- separating static posture from observed runtime behavior;
- reporting exported components, permission posture, network/storage indicators,
  and MASVS categories as static exposure indicators;
- avoiding claims that a static finding proves exploitation or runtime leakage;
- using runtime evidence to contextualize, not replace, static findings.

## Current ScytaleDroid Alignment

- The ML package has a shared `feature_matrix.py` contract for freeze/profile
  and operational query mode.
- Operational query-mode output now uses the configured dynamic evidence root
  rather than reconstructing paths from `output/`.
- Snapshot freezes record repeated app/build identities as
  `duplicate_identity_groups` instead of turning every repeated observation into
  a hard failure.
- Operational lint now emits warnings for duplicate build observations, fallback
  training, low-confidence groups, thin baselines, snapshot-freeze issues, and
  OCSVM fallback training.
- Query-mode snapshots persist lint warnings in both `operational_lint.json`
  and `snapshot_summary.json`.

## Recommended Follow-Ups

1. Keep the generated `method_basis` blocks in runtime ML manifests aligned
   with this note when model roles, provenance requirements, or reporting
   caveats change.
2. Promote duplicate build observations and thin baselines into table footnotes
   rather than burying them in JSON only.
3. Keep OCSVM as a supporting score unless a study-specific validation step
   proves it is stable enough to be a gate.
4. Stage a cleanup review for any stale `output/evidence/dynamic` material; do
   not treat it as authoritative evidence unless a report explicitly documents
   it.
5. Add a figure/table that separates static exposure score, runtime behavior
   score, and provenance confidence so readers do not infer a single blended
   value is direct exploitability.
