"""PM-locked ML defaults and schema versions for Paper #2."""

from __future__ import annotations


ML_SCHEMA_VERSION = 1
ML_SCHEMA_LABEL = f"v{ML_SCHEMA_VERSION}"

# Windowing (locked)
WINDOW_SIZE_S = 10.0
WINDOW_STRIDE_S = 5.0

# Thresholding (locked)
THRESHOLD_PERCENTILE = 95.0

# Seed derivation (locked)
SEED_SALT_LABEL = "paper2-ml-seed-salt-v1"
# Stable salt string. Do not change during Paper #2.
SEED_SALT = "scytaledroid-paper2-ml-seed-salt-v1"

# Models (locked)
MODEL_IFOREST = "isolation_forest"
MODEL_OCSVM = "one_class_svm"

