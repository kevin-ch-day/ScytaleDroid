from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple


ONLINE_URL = "https://developer.android.com/reference/android/Manifest.permission"


def _load_html_from_file(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None


def _fetch_online_html() -> Optional[str]:
    # Prefer requests if available for better TLS/timeouts; otherwise urllib
    try:
        import requests  # type: ignore

        try:
            r = requests.get(ONLINE_URL, timeout=20)
            r.raise_for_status()
            return r.text
        except Exception:
            return None
    except Exception:
        try:
            from urllib.request import urlopen

            with urlopen(ONLINE_URL, timeout=20) as resp:  # nosec - fixed URL
                data = resp.read()
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return None


def _find_sdk_manifest_doc() -> Optional[Path]:
    """Best-effort attempt to locate a local SDK Manifest.permission HTML.

    We search under ANDROID_SDK_ROOT or ANDROID_HOME for a doc path that
    resembles the reference HTML used by devsite. This is a heuristic: if we
    cannot find it, callers should fall back to the online URL.
    """

    roots = [
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
    ]
    for root in [Path(p) for p in roots if p]:
        # Common locations in offline docs; scan a few likely candidates
        candidates = [
            root / "docs" / "reference" / "android" / "Manifest.permission.html",
            root / "docs" / "offline" / "android" / "Manifest.permission.html",
        ]
        for path in candidates:
            if path.exists():
                return path
    return None


def load_permission_doc(source: str = "auto", *, file_path: Optional[Path] = None) -> Tuple[Optional[str], str]:
    """Return (html, source_label) from SDK or online docs.

    source: "sdk" | "online" | "auto"
    file_path: optional explicit file path
    """

    if file_path is not None:
        html = _load_html_from_file(file_path)
        if html:
            return html, f"file:{file_path.name}"

    if source not in {"sdk", "online", "auto"}:
        source = "auto"

    if source in {"sdk", "auto"}:
        local_path = _find_sdk_manifest_doc()
        if local_path is not None:
            html = _load_html_from_file(local_path)
            if html:
                return html, f"sdk:{local_path.name}"

    # fallback to online
    html = _fetch_online_html()
    if html:
        return html, "online"
    return None, "unavailable"

