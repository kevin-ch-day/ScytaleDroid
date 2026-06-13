# Experimental Static Exposure Math Spec

## Purpose

This document defines the first experimental math layer for ScytaleDroid static
exposure analytics.

It is intentionally:

- read-only
- measurement-oriented
- downstream of canonical static evidence
- outside canonical scoring
- outside DB schema change scope

It is not a replacement for canonical static findings, MASVS mappings,
permission posture, or dynamic evidence. It is an exploratory analysis layer
over evidence that already exists in the repo.

## Non-goals

This work must not:

- introduce a new canonical app score
- call any output `risk`, `overall risk`, `canonical risk`, `app risk score`,
  or `final score`
- change canonical tables or add schema requirements
- silently replace existing reporting or scoring contracts
- turn PCA or outlier distance into a production ranking without a separate
  design decision

## Positioning

MobSF is broad and report-oriented: static and dynamic scanning across mobile
targets with general analyst outputs. ScytaleDroid's differentiator is not
"more scanner findings." It is a device-native Android research pipeline with
tighter identity and corpus structure:

`inventory -> harvest -> base/split identity -> canonical static evidence -> category baselines -> dynamic handoff`

This spec keeps that posture. The experimental layer should measure variation
inside a real Android corpus, not imitate a generic scanner dashboard.

## Core object

Define the static exposure matrix:

`X ∈ R^(n × p)`

where:

- `n` = apps, packages, or package-build observations
- `p` = selected static exposure dimensions

Each row should represent one canonical static observation grain. For the first
pass, the preferred row grain is:

- one row per canonical `static_analysis_runs.id`
- one preferred run per package-build for any summary export

The first implementation should stay explicit about grain:

- package/build row
- session subset used
- category labels used
- missing dimensions by row

## Current repo data sources

The experimental layer should be derived from existing canonical or repo-owned
surfaces:

- `static_analysis_runs`
  - identity, hashes, JSON analytics payloads, reproducibility metadata
- `static_analysis_findings`
  - normalized findings with severity, detector, MASVS area/control, evidence
- `static_permission_matrix`
  - permission-level evidence
- `static_permission_risk_vnext`
  - permission posture details
- `permission_signal_observations`
  - permission governance and observation context where present
- `static_fileproviders`
  - provider / FileProvider posture
- `static_provider_acl`
  - provider path-permission detail
- `static_string_summary`
  - string-analysis rollups
- `static_string_samples`
  - supporting string evidence
- `apk_sets`
  - split/install-set identity and complexity hints
- `v_static_handoff_v1`
  - identity-tight static-to-dynamic readiness surface

The eventual implementation should be read-only and should not depend on legacy
`runs`, `metrics`, or `buckets` tables.

## Candidate exposure dimensions

The table below classifies candidate dimensions by present-day support in the
repo. "Strong" means the dimension is computable now with reasonably direct,
canonical evidence. "Partial" means the dimension exists but needs careful
scope limits or fallback logic. "Weak" means the repo has hints but not a
stable, defensible measurement surface yet.

| Dimension | Status today | Primary sources | Notes |
| --- | --- | --- | --- |
| Permission exposure | Strong today | `static_permission_matrix`, `static_permission_risk_vnext`, `permission_signal_observations` | Best-developed static posture surface. |
| Dangerous permission count | Strong today | `static_permission_matrix`, permission writers | Stable scalar. |
| Provider / FileProvider exposure | Strong today | `static_fileproviders`, `static_provider_acl`, canonical findings | Good exported/provider guard coverage. |
| Component exposure | Partial today | canonical findings, detector outputs, report JSON | Useful, but not yet one clean normalized component table across all component families. |
| Network / cleartext exposure | Strong today, if scoped narrowly | `static_string_summary`, `static_string_samples`, manifest/network security findings, run JSON | Strong for cleartext + endpoint posture; broader TLS/integrity nuance remains partial. |
| Storage / backup posture | Partial today | manifest flags, provider posture, findings | Strong signals exist, but broader storage posture is not one complete canonical vector yet. |
| Secrets / string exposure | Strong today | `static_string_summary`, `static_string_samples`, findings | Good counts and evidence for endpoints, cleartext, tokens, high-entropy strings. |
| MASVS privacy count | Strong today | `static_analysis_findings`, run matrices | Derived from canonical MASVS-tagged findings. |
| MASVS platform count | Strong today | `static_analysis_findings`, run matrices | Same as above. |
| MASVS network count | Strong today | `static_analysis_findings`, run matrices | Same as above. |
| MASVS storage count | Strong today | `static_analysis_findings`, run matrices | Same as above. |
| Split / install-set complexity | Strong today | `apk_sets`, artifact manifests, split-aware run metadata | Good candidate for structural complexity, not severity. |
| Evidence completeness proxy | Partial today | `static_analysis_runs`, `v_static_handoff_v1`, string/provider presence, hash fields | Useful as a data-quality axis; needs explicit proxy definition. |
| SDK inventory | Weak today | placeholder surfaces only | Do not include in first numeric model. |
| Crypto posture scalar | Weak today | findings exist, no clean broad summary vector yet | Future-only unless a narrow subset is defined. |
| WebView posture scalar | Weak today | findings exist, not a stable summary surface | Future-only. |
| Dynamic loading scalar | Weak today | placeholder / sparse detector surface | Future-only. |
| Native hardening scalar | Weak today | sparse findings only | Future-only. |

## First implementation subset

The first numeric model should only use dimensions that are strong today, plus
at most a small number of clearly labeled partial dimensions.

Recommended first subset:

1. permission exposure
2. dangerous permission count
3. provider / FileProvider exposure
4. network / cleartext exposure
5. secrets / string exposure
6. MASVS privacy count
7. MASVS platform count
8. MASVS network count
9. MASVS storage count
10. split / install-set complexity

Optional partial dimensions for a guarded first pass:

- storage / backup posture
- evidence completeness proxy

Do not include weak dimensions in the first numeric matrix.

## Feature definitions

The first implementation should prefer simple, auditable feature definitions.
Each feature must have:

- source table(s) or JSON path(s)
- row grain
- aggregation rule
- null/missing rule
- interpretation note

Recommended initial examples:

| Feature | Type | Definition sketch |
| --- | --- | --- |
| `permission_exposure_score` | scalar | Permission-scoped posture score already computed by the permission model. |
| `dangerous_permission_count` | count | Count of dangerous declared permissions for the run. |
| `provider_exposure_count` | count | Exported or broad provider/FileProvider signals from `static_fileproviders`. |
| `network_cleartext_signal_count` | count | Cleartext endpoint + cleartext policy indicators from string/network surfaces. |
| `secret_signal_count` | count | Secrets/high-entropy/token observations from string evidence. |
| `masvs_privacy_count` | count | Count of findings mapped to MASVS privacy category. |
| `masvs_platform_count` | count | Count of findings mapped to MASVS platform category. |
| `masvs_network_count` | count | Count of findings mapped to MASVS network category. |
| `masvs_storage_count` | count | Count of findings mapped to MASVS storage category. |
| `split_apk_count` | count | Number of APK files in the install set for the run. |
| `install_set_complexity` | scalar | Simple derived complexity from split/base count and manifest identity. |
| `evidence_completeness_ratio` | scalar, optional | Share of required evidence surfaces present for the run. |

All derived definitions must be documented next to the implementation script.

## Category baselines

Category baselines should be computed over categories such as:

- Social media
- Communication
- Shopping
- Finance
- Productivity
- Health & fitness
- Uncategorized

The category label source should remain the current repo mapping logic unless a
separate taxonomy migration is approved.

For each feature and category, compute:

- mean
- median
- standard deviation
- IQR
- MAD
- missingness
- sample count

### Guardrails

- if category `n < 5`, emit descriptive statistics only and mark the category
  as baseline-weak
- if `std = 0`, do not compute classical z-scores
- if `MAD = 0`, do not compute robust z-scores
- if missingness is high, emit the missingness rate alongside the baseline and
  suppress comparative claims
- if the feature is binary or near-binary, prefer proportion summaries over
  pretending it is continuous

## Standardized feature layer

For sufficiently supported features, define the classical z-score:

`z = (x - μ) / σ`

where:

- `x` = app feature value
- `μ` = category mean
- `σ` = category standard deviation

Use classical z-scores only when:

- category `n >= 5`
- `σ > 0`
- the feature is not dominated by extreme skew or zero inflation

## Robust standardized layer

Define the robust z-score:

`z_robust = 0.6745 * (x - median) / MAD`

where:

- `median` = category median
- `MAD` = median absolute deviation

Prefer robust z-scores when:

- sample sizes are modest
- the feature is skewed
- there are visible outliers
- category distributions are not close to normal

Suppress robust z-scores when:

- `MAD = 0`
- effective category support is too small
- the feature is almost entirely missing or constant

## PCA / SVD layer

PCA is an exploratory structure method, not a score.

The first PCA pass should use:

- a standardized exposure matrix over strong features only
- explicit filtering of rows with excessive missingness
- explicit imputation policy if imputation is used

Outputs:

- feature scaling summary
- complete-row count
- PCA components
- explained variance ratio
- feature loadings
- app coordinates on PC1 / PC2
- category distributions in PCA space

Questions PCA should answer:

- which dimensions explain the most variation?
- which apps are extreme on major components?
- do categories separate naturally or overlap heavily?

### PCA guardrails

- do not label PCA coordinates as a score
- do not order apps by PC1 and call it exposure severity
- report missingness before PCA
- skip PCA if the complete-row count is too small for the retained feature set
- skip PCA if the retained feature count is too small to provide structure

Practical starting gate:

- at least `max(20, 3p)` complete rows after feature filtering

## Robust outlier layer

The first outlier layer should be category-relative and descriptive.

### Per-dimension outliers

For each feature, compute:

- classical z-score when valid
- robust z-score when valid

Emit flags such as:

- `feature_high_outlier`
- `feature_low_outlier`
- `feature_outlier_method`

The method label matters because small categories should not silently mix
classical and robust interpretations.

### Multivariate outliers

Where category support is strong enough, compute Mahalanobis distance:

`D_M(x,C)^2 = (x - μ_C)^T Σ_C^-1 (x - μ_C)`

where:

- `x` = feature vector for one app
- `μ_C` = category location vector
- `Σ_C` = category covariance matrix

Use the label:

- `exposure_outlier_distance`

If a robust covariance estimator is available later, prefer robust location and
covariance estimation over naive covariance in skewed corpora.

### Multivariate outlier guardrails

- suggested gate: `n >= max(15, 3p)`
- if covariance is singular, skip the metric or use a documented regularized
  covariance estimator
- if categories are visibly multimodal, do not over-interpret one covariance
  ellipse as a full description
- never rename Mahalanobis distance to `risk`

## Information-theory layer

Define each app's MASVS/control-family distribution:

`p_app = [p_privacy, p_platform, p_network, p_storage, p_code, p_resilience]`

where each `p_i` is the normalized share of the app's mapped findings or
weighted control hits in that family.

Compute entropy:

`H(app) = -Σ p_i log(p_i)`

Interpretation:

- low entropy = exposure concentrated in a small number of control families
- high entropy = exposure spread across many control families

Recommended labels:

- `control_entropy`
- `control_dispersion`

### Jensen-Shannon distance

Use Jensen-Shannon distance for distribution-shape comparison between:

- an app and its category mean distribution
- category distributions
- later, version-to-version distributions

Recommended label:

- `js_control_distance`

### Information-theory guardrails

- require nonzero total mapped findings or weighted control mass
- use explicit smoothing if zero bins must be stabilized
- treat entropy and JSD as shape measures, not severity totals
- do not compare apps only by entropy without also reporting total evidence

## Optimal transport layer

Wasserstein distance is useful but should be treated as future or optional in
the first pass.

Potential later uses:

- category-level exposure distribution comparison
- version-to-version exposure movement
- static-to-dynamic distribution movement

Recommended labels:

- `exposure_distribution_distance`
- `exposure_movement`
- `version_drift_distance`

This should be deferred until simple per-feature and control-distribution
surfaces are stable.

## Graph / spectral layer

Graph methods are future-facing, not first-pass requirements.

Candidate graphs:

- app-app similarity graph from exposure vectors
- permission co-occurrence graph
- app-control bipartite graph
- app-SDK graph
- app-domain graph

Potential methods:

- degree centrality
- community detection
- spectral clustering
- graph-based outlier detection

First candidate outputs, once graph work starts:

- `permission_cooccurrence.csv`
- app similarity adjacency summaries
- component communities or category clusters

Graph methods should remain exploratory unless a separate contract defines the
meaning of each graph and similarity metric.

## Longitudinal layer

The repo should reserve a future longitudinal model for repeated captures.

Version drift:

`ΔX = X_t2 - X_t1`

Rate of drift:

`dX/dt ≈ (X_t2 - X_t1) / (t2 - t1)`

Cumulative exposure:

`AUC = ∫ S(t) dt`

This requires:

- repeat captures over time
- stable package/build identity
- retained evidence for comparison
- a clear policy for category drift and split/install-set change

Longitudinal metrics should not be implemented in the first pass unless the
dataset has repeated observations with trustworthy timestamps.

## Proposed first implementation

The first implementation should be one read-only script. A suitable repo-owned
surface would be:

- `scripts/db/report_static_exposure_analytics.py`

Behavior:

- read canonical DB surfaces only
- export CSV/JSON artifacts under `output/audit/static_exposure/<stamp>/`
- never write derived values back into canonical tables

Required outputs:

- `static_exposure_vectors.csv`
- `category_baselines.csv`
- `category_outliers.csv`
- `pca_components.csv`
- `pca_app_coordinates.csv`
- `masvs_entropy.csv`
- `js_control_distances.csv`
- `permission_cooccurrence.csv`
- `evidence_completeness_gaps.csv`
- `summary.json`

## Methods valid for the current dataset

The methods below are valid now, given current repo evidence surfaces:

- descriptive category baselines
- missingness analysis
- classical z-scores on well-behaved features with enough support
- robust z-scores on skewed features with nonzero MAD
- exploratory PCA on strong features with enough complete rows
- entropy over MASVS/control-family distributions
- Jensen-Shannon distance over normalized control distributions
- simple permission co-occurrence counts

These are the highest-value first methods because they match current evidence
quality and do not require pretending the dataset is cleaner or denser than it
is.

## Methods that need more data or stronger contracts

The methods below should wait for better data coverage, stronger normalized
surfaces, or repeated observations:

- robust Mahalanobis distance on small categories
- any multivariate outlier metric over weak or heavily missing features
- Wasserstein movement metrics
- longitudinal drift / derivative / AUC analysis
- app-SDK graph analytics
- app-domain graph analytics beyond simple endpoint counts
- broad component-exposure vectors unless component normalization improves
- any crypto/WebView/native/dynamic-loading scalar treated as a first-class
  exposure dimension

## Statistical guardrails

The implementation must surface its own limits.

Minimum guardrails:

- always report sample counts
- always report missingness
- distinguish zero from missing
- suppress z-scores when denominator is zero
- suppress robust z-scores when `MAD = 0`
- suppress category comparisons when category `n < 5`
- suppress multivariate distance when `n < max(15, 3p)`
- do not silently impute without documenting the method
- keep feature scaling explicit in PCA outputs
- keep exploratory outputs labeled exploratory
- do not collapse all outputs into one scalar

## Naming contract

Allowed language:

- exposure vector
- exposure matrix
- category baseline
- exposure outlier
- control entropy
- control dispersion
- evidence completeness
- experimental measurement

Forbidden language:

- overall risk
- canonical risk
- app risk score
- final score

## Dependencies

The first pass can be split into core and optional dependencies.

Core likely needed:

- existing repo DB/query stack
- `csv`, `json`, `math`, `statistics`
- `numpy`
- `pandas`

Optional but recommended:

- `scipy`
  - entropy
  - Jensen-Shannon distance
  - Wasserstein distance later
- `scikit-learn`
  - PCA
  - robust covariance / `MinCovDet`
  - spectral clustering later

If optional packages are absent, the script should:

- degrade gracefully
- record which outputs were skipped
- never silently emit partial math as if the full pipeline ran

## Why this helps ScytaleDroid beat MobSF without becoming MobSF

This layer improves ScytaleDroid by making it better at corpus measurement, not
by chasing generic scanner breadth.

Benefits:

- category-relative baselines convert one-off findings into comparative Android
  corpus structure
- PCA and entropy reveal structure that line-item reports do not show
- outlier distances identify unusual apps without pretending to know real-world
  harm
- split/install-set complexity and evidence completeness preserve
  ScytaleDroid's device-native identity advantage
- the outputs remain compatible with later dynamic handoff and repeatability
  work

In short, MobSF is useful for broad inspection. ScytaleDroid should win on
research-grade corpus measurement, reproducible identity, and static-to-dynamic
continuity.

## Reference notes

This spec aligns with the current repo architecture and with external
references for the exploratory methods:

- MobSF documentation and README for report-oriented static/dynamic positioning
- scikit-learn PCA documentation for variance-explaining components
- scikit-learn covariance documentation and `MinCovDet` for robust covariance
  and Mahalanobis distance
- SciPy entropy, Jensen-Shannon, and Wasserstein documentation for
  distributional comparison methods
- scikit-learn spectral clustering documentation for future graph/similarity
  exploration

Suggested links:

- https://mobsf.github.io/docs/
- https://github.com/MobSF/Mobile-Security-Framework-MobSF
- https://scikit-learn.org/stable/modules/generated/sklearn.decomposition.PCA.html
- https://scikit-learn.org/stable/modules/covariance.html
- https://scikit-learn.org/stable/modules/generated/sklearn.covariance.MinCovDet.html
- https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.entropy.html
- https://docs.scipy.org/doc/scipy/reference/generated/scipy.spatial.distance.jensenshannon.html
- https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.wasserstein_distance.html
- https://scikit-learn.org/stable/modules/generated/sklearn.cluster.SpectralClustering.html
