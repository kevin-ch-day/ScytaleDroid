"""Operational ML defaults (Phase F2+).

These settings apply to query-mode / operational snapshots under output/operational/.

Contract:
- Phase E (Paper #2) is controlled by ml_parameters_paper2.py and remains frozen.
- Operational mode may evolve; changes here should be accompanied by snapshot manifests.
"""

from __future__ import annotations

# Keep the schema label consistent with Phase E for now (same output shape), but the
# *semantics* are operational (stabilised features, extra diagnostic tables).
ML_SCHEMA_VERSION = 1
ML_SCHEMA_LABEL = f"v{ML_SCHEMA_VERSION}"

# Windowing (keep consistent with Phase E to preserve comparability).
WINDOW_SIZE_S = 10.0
WINDOW_STRIDE_S = 5.0

# Thresholding
THRESHOLD_PERCENTILE = 95.0

# Determinism: explicitly pin the NumPy percentile algorithm.
NP_PERCENTILE_METHOD = "linear"

# Training quality gates (same defaults as Phase E; adjust later if needed).
MIN_WINDOWS_BASELINE = 30
MIN_PCAP_BYTES_FALLBACK = 100_000

# Audit threshold
MIN_TRAINING_SAMPLES_WARNING = 50

# Feature stabilisation (Phase F2)
FEATURE_LOG1P = True
FEATURE_ROBUST_SCALE = True
FEATURE_WINSORIZE = True
FEATURE_WINSORIZE_LOWER_PCT = 1.0
FEATURE_WINSORIZE_UPPER_PCT = 99.0

# Models (match Phase E set)
MODEL_IFOREST = "isolation_forest"
MODEL_OCSVM = "one_class_svm"

# Operational tuning defaults (safe, deterministic).
IFOREST_N_ESTIMATORS = 300
IFOREST_MAX_SAMPLES = "auto"
IFOREST_BOOTSTRAP = False
OCSVM_KERNEL = "rbf"
OCSVM_NU = 0.03
OCSVM_GAMMA = "scale"
OCSVM_SHRINKING = False
OCSVM_TOL = 1e-3

# Seed derivation
SEED_SALT_LABEL = "operational-ml-seed-salt-v1"
SEED_SALT = "scytaledroid-operational-ml-seed-salt-v1"
