from .version import (
    APP_AUTHOR,
    APP_DESCRIPTION,
    APP_NAME,
    APP_RELEASE,
    APP_VERSION,
    GITHUB_REPO,
)

# Paths
DATA_DIR   = "data"
OUTPUT_DIR = "output"
LOGS_DIR   = "logs"
STATIC_ANALYSIS_RETENTION_DAYS = 30
DYNAMIC_MIN_DURATION_S = 120
DYNAMIC_TARGET_DURATION_S = 180

# Dynamic dataset QA (Paper #2)
# Default can be overridden at process start via SCYTALEDROID_MIN_PCAP_BYTES.
# Env is read at import time (entrypoint default) and must not be read mid-run.
import os  # noqa: E402

try:
    DYNAMIC_MIN_PCAP_BYTES = int(os.getenv("SCYTALEDROID_MIN_PCAP_BYTES", "100000"))
except Exception:
    DYNAMIC_MIN_PCAP_BYTES = 100000

# Dataset protocol (Paper #2)
# Default can be overridden at process start via:
# - SCYTALEDROID_DATASET_BASELINE_RUNS
# - SCYTALEDROID_DATASET_INTERACTIVE_RUNS
# - SCYTALEDROID_DATASET_RUNS_PER_APP (legacy total override)
# This affects quota tracking and UI suggestions only; it does not change capture behavior.
try:
    DYNAMIC_DATASET_BASELINE_RUNS = int(os.getenv("SCYTALEDROID_DATASET_BASELINE_RUNS", "1"))
except Exception:
    DYNAMIC_DATASET_BASELINE_RUNS = 1

try:
    DYNAMIC_DATASET_INTERACTIVE_RUNS = int(os.getenv("SCYTALEDROID_DATASET_INTERACTIVE_RUNS", "2"))
except Exception:
    DYNAMIC_DATASET_INTERACTIVE_RUNS = 2

try:
    # If explicitly provided, treat this as an override for the total target runs.
    # Otherwise, derive it from baseline+interactive targets.
    _runs_total_env = os.getenv("SCYTALEDROID_DATASET_RUNS_PER_APP")
    if _runs_total_env is None:
        DYNAMIC_DATASET_RUNS_PER_APP = int(DYNAMIC_DATASET_BASELINE_RUNS) + int(DYNAMIC_DATASET_INTERACTIVE_RUNS)
    else:
        DYNAMIC_DATASET_RUNS_PER_APP = int(_runs_total_env)
except Exception:
    DYNAMIC_DATASET_RUNS_PER_APP = int(DYNAMIC_DATASET_BASELINE_RUNS) + int(DYNAMIC_DATASET_INTERACTIVE_RUNS)

# Device module paths
DEVICE_STATE_DIR = "state"
DEVICE_STATE_FILE = "active_device.json"

# UI preferences
DEFAULT_UI_TIMEZONES = {
    "Minneapolis, USA": "America/Chicago",
    "Las Vegas, USA": "America/Los_Angeles",
    "Dubai, UAE": "Asia/Dubai",
    "Paris, France": "Europe/Paris",
    "London, United Kingdom": "Etc/UTC",
}
UI_MAX_CLOCKS = 3
UI_TIMEZONES = {
    label: tz
    for label, tz in list(DEFAULT_UI_TIMEZONES.items())[:UI_MAX_CLOCKS]
}
UI_PRIMARY_CLOCK = "Minneapolis, USA"
UI_LOCAL_TIME_LABEL = UI_PRIMARY_CLOCK
UI_LOCAL_TIMEZONE = UI_TIMEZONES.get(UI_LOCAL_TIME_LABEL, "Etc/UTC")
UI_CLOCK_REFERENCE_MODE = "now"
UI_CLOCK_REFERENCE_LABEL = "Live (current time)"
UI_CLOCK_REFERENCE_TIMEZONE = UI_LOCAL_TIMEZONE
UI_CLOCK_REFERENCE_UTC = None

# Logging behaviour
ENABLE_CONSOLE_LOGS = False

# Harvest behaviour
HARVEST_DEDUP_SHA256 = True
HARVEST_KEEP_LAST = 1
HARVEST_WRITE_DB = True
HARVEST_WRITE_META = True
HARVEST_META_FIELDS = (
    "package_name",
    "app_label",
    "installer",
    "version_name",
    "version_code",
    "file_name",
    "file_size",
    "source_path",
    "local_path",
    "sha256",
    "sha1",
    "md5",
    "captured_at",
    "session_stamp",
    "device_serial",
    "pull_mode",
    "is_split_member",
    "split_group_id",
    "apk_id",
    "occurrence_index",
    "category",
    "artifact",
)

# Device analysis tuning
DEVICE_PROPERTY_KEYS = {
    "ro.product.brand": "brand",
    "ro.product.manufacturer": "manufacturer",
    "ro.product.model": "model",
    "ro.product.device": "device",
    "ro.product.name": "product",
    "ro.hardware": "hardware",
    "ro.build.version.release": "android_version",
    "ro.build.version.sdk": "sdk_level",
    "ro.build.display.id": "build_id",
    "ro.boot.qemu": "is_emulator_flag",
    "ro.hardware.chipname": "chipset",
    "ro.build.tags": "build_tags",
}
