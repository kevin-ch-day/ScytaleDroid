"""Facebook-specific scripted templates."""

from __future__ import annotations

SCRIPT_STEPS_FACEBOOK_BASIC_V2: tuple[tuple[str, str, int], ...] = (
    ("open_app", "Open Facebook app and settle on Home feed.", 20),
    ("open_profile_page", "Open your profile page briefly, then return.", 20),
    ("open_friends_scroll", "Open Friends tab/page and scroll briefly.", 20),
    ("open_add_friends_review", "Open add-friends / friend-requests surface and review briefly (no add/accept actions).", 20),
    ("create_text_post_draft", "Open text post composer, type short draft, then discard.", 25),
    ("create_photo_post_draft", "Open photo post composer, attach one photo draft, then discard.", 30),
    ("open_reels", "Open Reels and watch/scroll briefly.", 25),
    ("view_stories", "Open Stories and view 1-2 segments briefly.", 25),
    ("open_marketplace", "Open Marketplace briefly and scroll.", 20),
    ("open_notifications", "Open Notifications and scroll slightly.", 20),
    ("hold_foreground", "Remain on foreground until timer completes.", 0),
)

SCRIPT_STEPS_FACEBOOK_BEHAVIOR_V3: tuple[tuple[str, str, int], ...] = (
    ("home_feed", "Open Facebook Home feed and hold without scrolling.", 35),
    ("profile_view", "Open profile page and hold.", 25),
    ("profile_return_home", "Return Home from profile and hold briefly.", 20),
    ("friends_view", "Open Friends page and hold.", 20),
    ("friends_scroll", "Scroll Friends page slowly.", 15),
    ("friend_suggestions_view", "Open Suggestions / People You May Know and hold.", 20),
    ("friend_suggestions_scroll", "Scroll suggestions slowly.", 15),
    ("friends_return_view", "Return to Friends page and hold.", 20),
    ("friend_request_accept_1", "If visible and controlled, accept/add one known control friend request; otherwise mark limited or skip.", 15),
    ("friend_request_accept_2", "If visible and controlled, accept/add a second known control friend request; otherwise mark limited or skip.", 15),
    ("text_post_composer_open_1", "Open text post composer for test post 1.", 10),
    ("text_post_submit_1", "Submit test text post 1 in active mode; draft/discard in draft mode.", 30),
    ("text_post_return_home_1", "Return Home after text post 1 and settle.", 15),
    ("text_post_composer_open_2", "Open text post composer for optional repeat 2.", 10),
    ("text_post_submit_2", "Submit test text post 2 in active mode; draft/discard in draft mode.", 30),
    ("text_post_return_home_2", "Return Home after text post 2 and settle.", 15),
    ("text_post_composer_open_3", "Open text post composer for optional repeat 3.", 10),
    ("text_post_submit_3", "Submit test text post 3 in active mode; draft/discard in draft mode.", 30),
    ("text_post_return_home_3", "Return Home after text post 3 and settle.", 15),
    ("photo_post_composer_open_1", "Open photo post composer for test photo post 1.", 10),
    ("photo_attach_1", "Attach a safe test image for photo post 1.", 15),
    ("photo_post_submit_1", "Submit photo post 1 in active mode; draft/discard in draft mode.", 45),
    ("photo_post_return_home_1", "Return Home after photo post 1 and settle.", 15),
    ("photo_post_composer_open_2", "Open photo post composer for optional repeat 2.", 10),
    ("photo_attach_2", "Attach a safe test image for optional photo post 2.", 15),
    ("photo_post_submit_2", "Submit photo post 2 in active mode; draft/discard in draft mode.", 45),
    ("photo_post_return_home_2", "Return Home after photo post 2 and settle.", 15),
    ("photo_post_composer_open_3", "Open photo post composer for optional repeat 3.", 10),
    ("photo_attach_3", "Attach a safe test image for optional photo post 3.", 15),
    ("photo_post_submit_3", "Submit photo post 3 in active mode; draft/discard in draft mode.", 45),
    ("photo_post_return_home_3", "Return Home after photo post 3 and settle.", 15),
    ("reels_watch_first", "Open Reels and watch the first reel for 20s.", 25),
    ("reels_scroll", "Scroll once in Reels.", 5),
    ("reels_watch_2", "Watch the next Reel for 20s.", 20),
    ("reels_return_home", "Return Home from Reels and settle.", 15),
    ("stories_view_first", "Open Stories and view one segment for 15-20s.", 25),
    ("stories_return_home", "Return Home from Stories and settle.", 15),
    ("marketplace_view", "Open Marketplace and hold.", 25),
    ("marketplace_scroll", "Scroll Marketplace slowly.", 20),
    ("marketplace_return_home", "Return Home from Marketplace and settle.", 15),
    ("notifications_view", "Open Notifications and hold.", 20),
    ("notifications_scroll", "Scroll Notifications slowly.", 15),
    ("notifications_return_home", "Return Home from Notifications and settle.", 15),
    ("final_home_hold", "Remain on Home feed until target duration completes.", 0),
)

V3_SCRIPTED_REPRO_TIPS_FACEBOOK: dict[str, tuple[str, ...]] = {
    "facebook_behavior_v3": (
        "Use the controlled Facebook test account only.",
        "Active mode may publish/delete test content; record cleanup as its own phase if measured during capture.",
        "Use H+Enter to record a manual return-home/reset marker whenever the UI is on the wrong surface.",
    ),
}

__all__ = [
    "SCRIPT_STEPS_FACEBOOK_BASIC_V2",
    "SCRIPT_STEPS_FACEBOOK_BEHAVIOR_V3",
    "V3_SCRIPTED_REPRO_TIPS_FACEBOOK",
]
