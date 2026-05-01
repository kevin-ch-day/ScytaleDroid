"""Single place for inventory refresh wording (menus, progress, prompts, scripts).

Sentence-case matches Device Analysis menu option 1; tweak copy here only.
"""

from __future__ import annotations

SECTION_HEADLINE = "Refresh inventory"
FEEDBACK_ACTION = SECTION_HEADLINE
ERROR_SECTION = SECTION_HEADLINE

SCOPE_MENU_SUBTITLE = "Full device (ADB) or profile packages only"
PROFILE_MENU_SUBTITLE = "Choose profile"

MENU_OPTION_FULL = "Full device (all packages)"
MENU_OPTION_SCOPED = "Profile packages only (faster)"

RUN_START_HEADER = "Refresh inventory · start"
RUN_START_CARD_FOOTER = (
    "Packages are listed via ADB, saved as JSON snapshots under data/state, "
    "and app definitions sync to the database when it is enabled."
)

SUMMARY_BOX_TITLE = "Refresh inventory · summary"

PROGRESS_FOOTER_TIP = (
    "Next: ADB package dump → local snapshot files → optional DB app-definition sync. "
    "(Live line · paths/metadata = APK install paths + pm-detail work completed per package.)"
)

# When full sync wrote JSON but device_inventory_snapshots / device_inventory did not get a row.
DB_JSON_ONLY_EXPECTED = (
    "Database is disabled or not configured — snapshot is on disk under data/state only; "
    "SQL inventory tables were not written (expected for this mode)."
)

DB_MIRROR_FAILED = (
    "Snapshot JSON was saved, but inventory tables were not updated in the database. "
    "Check DB connectivity, schema gate, and logs; SQL reports may miss this run."
)

HARVEST_HINT_REFRESH_FIRST = (
    "Refresh inventory is recommended before execute harvest; "
    "an older snapshot may miss device changes."
)
HARVEST_CANCELLED_UNTIL_REFRESH = "Execute harvest cancelled until refresh inventory is run."
SNAPSHOT_NOT_FOUND = "No inventory snapshot found. Run refresh inventory first."

PROMPT_RUN_REFRESH_BEFORE_HARVEST = "Run refresh inventory before execute harvest?"
SYNC_COMPLETED_GUARD_BRIEF = "Refresh inventory completed before execute harvest."

BANNER_REFRESH_REQUIRED = "Refresh inventory required"

MAIN_INTERRUPT_NOTICE = (
    "Stopped · last persisted snapshot unchanged. Use refresh inventory again when ready."
)
