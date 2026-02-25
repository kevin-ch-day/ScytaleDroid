"""PM-locked ML defaults and schema versions for the canonical freeze/profile.

Notes:
- These constants are treated as a reproducibility contract.
- Changing them may change derived outputs (fingerprints, thresholds, scores).
"""

from __future__ import annotations

ML_SCHEMA_VERSION = 1
ML_SCHEMA_LABEL = f"v{ML_SCHEMA_VERSION}"

# Capture/freeze contract versions (kept for back-compat with existing manifests).
PAPER_CONTRACT_VERSION = 1
REASON_TAXONOMY_VERSION = 1
FREEZE_CONTRACT_VERSION = 1
PAPER_EXPORT_SCHEMA_VERSION = 1

# Report/bundle schema (publication-facing). Bump only when table/figure schemas or formatting contracts change.
# v2: adds Table 7 and clarifies Table 5 column naming (`finding_count_*`).
REPORT_SCHEMA_VERSION = 2

# Canonical dataset anchor filename (stable; dataset identity is the hash inside the JSON).
FREEZE_CANONICAL_FILENAME = "dataset_freeze.json"

# Messaging cohort (used for exemplar selection + optional stratification).
MESSAGING_PACKAGES = {
    "com.facebook.orca",  # Facebook Messenger
    "org.thoughtcrime.securesms",  # Signal
    "org.telegram.messenger",  # Telegram
    "com.whatsapp",  # WhatsApp
}

# Friendly labels used in publication-facing tables/figures (bundle only).
DISPLAY_NAME_BY_PACKAGE = {
    "com.facebook.katana": "Facebook",
    "com.facebook.orca": "Facebook Messenger",
    "com.instagram.android": "Instagram",
    "com.linkedin.android": "LinkedIn",
    "com.pinterest": "Pinterest",
    "com.reddit.frontpage": "Reddit",
    "org.thoughtcrime.securesms": "Signal",
    "com.snapchat.android": "Snapchat",
    "org.telegram.messenger": "Telegram",
    "com.zhiliaoapp.musically": "TikTok",
    "com.whatsapp": "WhatsApp",
    "com.twitter.android": "X",
}

# Windowing (locked)
WINDOW_SIZE_S = 10.0
WINDOW_STRIDE_S = 5.0

# Sampling duration contract
MIN_SAMPLING_SECONDS = 180.0
RECOMMENDED_SAMPLING_SECONDS = 240.0

# Thresholding (locked)
THRESHOLD_PERCENTILE = 95.0

# Determinism lock: explicitly pin the NumPy percentile algorithm.
NP_PERCENTILE_METHOD = "linear"

# Training quality gates
MIN_WINDOWS_BASELINE = 30

# Baseline PCAP bytes gate (manifest value wins if present).
MIN_PCAP_BYTES = 50_000
MIN_PCAP_BYTES_FALLBACK = MIN_PCAP_BYTES

# ML audit thresholds
MIN_TRAINING_SAMPLES_WARNING = 50

# Feature transforms (defaults to legacy behavior)
FEATURE_LOG1P = False
FEATURE_ROBUST_SCALE = False

# Seed derivation (locked)
SEED_SALT_LABEL = "paper2-ml-seed-salt-v1"
SEED_SALT = "scytaledroid-paper2-ml-seed-salt-v1"

# Models (locked)
MODEL_IFOREST = "isolation_forest"
MODEL_OCSVM = "one_class_svm"

# Model hyperparameters (locked)
IFOREST_N_ESTIMATORS = 200
IFOREST_MAX_SAMPLES = "auto"
IFOREST_BOOTSTRAP = False
OCSVM_KERNEL = "rbf"
OCSVM_NU = 0.05
OCSVM_GAMMA = "scale"
OCSVM_SHRINKING = False
OCSVM_TOL = 1e-3

# Fig B1 exemplar selection (locked)
EXEMPLAR_ALLOWED_INTERACTION_TAGS = {"voice", "video"}

