# Application metadata
APP_NAME        = "ScytaleDroid"
APP_VERSION     = "0.0.1"
APP_RELEASE     = "alpha"
APP_DESCRIPTION = "Android Security Research Platform"
APP_AUTHOR      = "Kevin Day"

#Github
GITHUB_REPO = "https://github.com/kevin-ch-day/ScytaleDroid"

# Paths
DATA_DIR   = "data"
OUTPUT_DIR = "output"
LOGS_DIR   = "logs"

# Device module paths
DEVICE_STATE_DIR = "state"
DEVICE_STATE_FILE = "active_device.json"

# Logging behaviour
ENABLE_CONSOLE_LOGS = False

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
