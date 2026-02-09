"""PM-locked ML defaults and schema versions for Paper #2."""

from __future__ import annotations


ML_SCHEMA_VERSION = 1
ML_SCHEMA_LABEL = f"v{ML_SCHEMA_VERSION}"

# Report/bundle schema (paper-facing). Bump only when table/figure schemas or formatting contracts change.
# v2: adds Table 7 and clarifies Table 5 column naming (`finding_count_*`).
REPORT_SCHEMA_VERSION = 2

# Canonical Paper #2 dataset anchor (PM/reviewer locked).
# Phase E must select ONLY `included_run_ids` from this freeze file and fail closed if
# it is missing or not checksummed.
FREEZE_CANONICAL_FILENAME = "dataset_freeze-20260208T201527Z.json"

# Messaging cohort for Paper #2 (used for exemplar selection + optional stratification).
# This must remain stable for Paper #2.
MESSAGING_PACKAGES = {
    "com.facebook.orca",  # Facebook Messenger
    "org.thoughtcrime.securesms",  # Signal
    "org.telegram.messenger",  # Telegram
    "com.whatsapp",  # WhatsApp
}

# Friendly labels used in paper-facing tables/figures (bundle only). Keep stable for Paper #2.
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

# Thresholding (locked)
THRESHOLD_PERCENTILE = 95.0

# Determinism lock: explicitly pin the NumPy percentile algorithm (do not rely on defaults).
# This is a paper toolchain contract; changing it after a freeze is a new snapshot/version.
NP_PERCENTILE_METHOD = "linear"

# Training quality gates (reviewer-approved defaults; Paper #2)
# Minimum number of baseline windows required for baseline-only training.
# With 10s/5s windowing, ~180s baseline -> ~35 windows.
MIN_WINDOWS_BASELINE = 30

# PCAP bytes gate fallback (manifest value wins if present).
MIN_PCAP_BYTES_FALLBACK = 100_000

# ML audit thresholds (Phase F1)
# Warning threshold for training sample size; does not affect model fitting.
MIN_TRAINING_SAMPLES_WARNING = 50

# Feature transforms (Phase F1 opt-in, defaults to legacy behavior)
FEATURE_LOG1P = False
FEATURE_ROBUST_SCALE = False

# Seed derivation (locked)
SEED_SALT_LABEL = "paper2-ml-seed-salt-v1"
# Stable salt string. Do not change during Paper #2.
SEED_SALT = "scytaledroid-paper2-ml-seed-salt-v1"

# Models (locked)
MODEL_IFOREST = "isolation_forest"
MODEL_OCSVM = "one_class_svm"

# Fig B1 exemplar selection (PM locked)
# Exemplar must be a messaging app and must be a call (voice or video).
EXEMPLAR_ALLOWED_INTERACTION_TAGS = {"voice", "video"}
