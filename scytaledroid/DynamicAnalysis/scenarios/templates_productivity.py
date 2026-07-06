"""Cloud/productivity/RTC scripted templates and reproducibility tips."""

from __future__ import annotations

SCRIPT_STEPS_CLOUD_PRODUCTIVITY_BASIC_V1: tuple[tuple[str, str, int], ...] = (
    ("sign_in_if_prompted", "If prompted, sign in with the test account; otherwise continue without changes.", 25),
    ("browse_files", "Browse recent files/documents/notes and open the file browser/list surface.", 25),
    ("open_item", "Open any item (file/doc/sheet/note/PDF) and scroll within it briefly.", 40),
    ("upload_or_import_preview", "If available: start an upload/import/add-file flow (e.g., to Drive/Dropbox) then cancel before final commit; otherwise skip.", 30),
    ("search_in_app", "Use in-app search/find briefly, then return.", 25),
    ("open_account_settings", "Open account/settings/help surface briefly, then return.", 20),
    ("sign_out_optional", "Optional: view sign-out option but do not sign out unless explicitly required for the runbook.", 10),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_DRIVE_BROWSE_SEARCH_OPEN_STAR_V1 = (
    ("wait_settle", "Wait on the home surface to allow sync/metadata to settle.", 10),
    ("search_short_term", "Use Search: type fixed term (e.g., 'report') and execute search.", 25),
    ("wait_after_search", "Wait after search results load.", 15),
    ("open_folder_scroll", "Open a folder and scroll 2-3 swipes (no file edits).", 25),
    ("wait_after_folder", "Wait after browsing folder listing.", 10),
    ("open_file_preview", "Open a file preview (PDF/Doc) and keep it open briefly, then back.", 25),
    ("pull_to_refresh", "Pull-to-refresh once on the list surface.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_DOCS_OPEN_EDIT_COMMENT_REFRESH_V1 = (
    ("wait_settle", "Wait on the document list surface to settle.", 10),
    ("open_known_doc", "Open a known existing document (same doc each run).", 25),
    ("wait_in_doc", "Wait in the document for content sync/autosave to stabilize.", 20),
    ("type_10_chars", "Tap body and type ~10 characters, then pause (non-destructive if possible).", 20),
    ("undo_redo", "Undo then redo once, then pause.", 20),
    ("add_comment_optional", "Optional: add a comment on a word/selection; skip if UI differs.", 25),
    ("back_to_list_refresh", "Return to list and pull-to-refresh once.", 25),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_SHEETS_OPEN_EDIT_SORT_ROW_REFRESH_V1 = (
    ("wait_settle", "Wait on the sheet list surface to settle.", 10),
    ("open_known_sheet", "Open a known existing sheet (same sheet each run).", 25),
    ("wait_in_sheet", "Wait in the sheet for grid load/sync to stabilize.", 20),
    ("edit_two_cells", "Edit two cells (e.g., add 1 then 2), then pause.", 25),
    ("sort_or_filter_optional", "Optional: apply a simple sort/filter; skip if not found.", 25),
    ("insert_row_optional", "Optional: insert a new row; skip if not found.", 20),
    ("exit_to_list_refresh", "Exit to list and pull-to-refresh once.", 25),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_RTC_COLLABORATION_BASIC_V1 = (
    ("open_home", "Open the app and settle on the home surface.", 20),
    ("open_meeting_surface", "Open new meeting/join meeting/calls surface (do not start a call), then return.", 25),
    ("open_chat_or_channels", "Open chat/channels/contacts surface briefly, then return.", 25),
    ("open_profile_settings", "Open profile/settings surface briefly, then return.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_ZOOM_JOIN_AUDIO_ONLY_V1 = (
    ("wait_settle", "Wait on the home surface to settle.", 10),
    ("tap_join_meeting", "Tap Join (do not host/start).", 15),
    ("enter_meeting_id_fixed", "Enter fixed Meeting ID (same every run).", 20),
    ("enter_name_fixed_join", "Enter fixed display name (same every run) and join.", 20),
    ("join_internet_audio_camera_off", "Join with Internet audio; keep Camera OFF (consistent).", 25),
    ("in_meeting_hold_audio_only", "Stay connected audio-only for ~90-120s (no chat/reactions).", 120),
    ("leave_meeting_confirm", "Leave meeting and confirm.", 15),
    ("return_home_wait", "Return to home and wait briefly.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

SCRIPT_STEPS_MEET_JOIN_MIC_ON_CAM_OFF_V1 = (
    ("wait_settle", "Wait on the home surface to settle.", 10),
    ("tap_join_with_code", "Tap Join with a code (or equivalent).", 15),
    ("enter_meeting_code_fixed", "Enter fixed meeting code (same every run).", 20),
    ("prejoin_set_cam_off_mic_on", "On pre-join: Camera OFF; Mic ON (or OFF, but be consistent).", 20),
    ("tap_join", "Join meeting.", 10),
    ("in_meeting_hold", "Stay connected ~90-120s (no chat/reactions).", 120),
    ("leave_meeting_confirm", "Leave meeting and confirm.", 15),
    ("return_home_wait", "Return to home and wait briefly.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 45),
)

V3_BASELINE_REPRO_TIPS_PRODUCTIVITY: dict[str, tuple[str, ...]] = {
    "com.google.android.apps.docs": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Drive home surface; do not open files, search, or scroll.",
    ),
    "com.google.android.apps.docs.editors.docs": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Docs list surface; do not open a doc, search, or scroll.",
    ),
    "com.google.android.apps.docs.editors.sheets": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Sheets list surface; do not open a sheet, search, or scroll.",
    ),
    "us.zoom.videomeetings": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Zoom home/landing screen; do not join/host/schedule.",
    ),
    "com.google.android.apps.tachyon": (
        "Recommended: force-stop the app before starting the baseline idle.",
        "Stay on the Meet home screen; do not join/create a meeting.",
    ),
}

V3_SCRIPTED_REPRO_TIPS_PRODUCTIVITY: dict[str, tuple[str, ...]] = {
    "drive_browse_search_open_star_v1": (
        "Use the same fixed search term each run (e.g., 'report').",
        "Prefer the same folder/file targets each run (pin to Recent if possible).",
    ),
    "docs_open_edit_comment_refresh_v1": (
        "Use the same known document each run (pin to Recent).",
        "Keep edits non-destructive (type small text, undo/redo); avoid sharing/sending.",
    ),
    "sheets_open_edit_sort_row_refresh_v1": (
        "Use the same known sheet each run (pin to Recent).",
        "Keep edits non-destructive; skip sort/filter/insert if the UI doesn't match.",
    ),
    "zoom_join_audio_only_v1": (
        "Use the same Meeting ID + display name every run.",
        "Keep camera OFF unless the template explicitly says otherwise; do not background the app.",
    ),
    "meet_join_mic_on_cam_off_v1": (
        "Use the same meeting code every run (a controlled test room).",
        "Keep camera/mic policy consistent; do not background the app.",
    ),
}

__all__ = [
    "SCRIPT_STEPS_CLOUD_PRODUCTIVITY_BASIC_V1",
    "SCRIPT_STEPS_DRIVE_BROWSE_SEARCH_OPEN_STAR_V1",
    "SCRIPT_STEPS_DOCS_OPEN_EDIT_COMMENT_REFRESH_V1",
    "SCRIPT_STEPS_SHEETS_OPEN_EDIT_SORT_ROW_REFRESH_V1",
    "SCRIPT_STEPS_RTC_COLLABORATION_BASIC_V1",
    "SCRIPT_STEPS_ZOOM_JOIN_AUDIO_ONLY_V1",
    "SCRIPT_STEPS_MEET_JOIN_MIC_ON_CAM_OFF_V1",
    "V3_BASELINE_REPRO_TIPS_PRODUCTIVITY",
    "V3_SCRIPTED_REPRO_TIPS_PRODUCTIVITY",
]
