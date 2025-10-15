from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple


ONLINE_URL = "https://developer.android.com/reference/android/Manifest.permission"

_ADDITIONAL_DOC_URLS = (
    "https://developer.android.com/reference/android/adservices/common/AdServicesPermissions",
)


@dataclass(frozen=True)
class _SdkDocCandidate:
    """Describe a potential SDK documentation asset."""

    relative_path: str


def additional_doc_urls() -> Sequence[str]:
    """Return extra documentation URLs that should be merged into the catalog."""

    return _ADDITIONAL_DOC_URLS


def _load_html_from_file(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None


def _fetch_online_html(url: str) -> Optional[str]:
    # Prefer requests if available for better TLS/timeouts; otherwise urllib
    try:
        import requests  # type: ignore

        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            return r.text
        except Exception:
            return None
    except Exception:
        try:
            from urllib.request import urlopen

            with urlopen(url, timeout=20) as resp:  # nosec - fixed URL
                data = resp.read()
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return None


def _sdk_roots() -> Iterable[Path]:
    roots = [
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
    ]
    for root in [Path(p) for p in roots if p]:
        yield root


def _find_sdk_doc(candidates: Sequence[_SdkDocCandidate]) -> Optional[Path]:
    """Return the first matching SDK documentation path from the provided list."""

    for root in _sdk_roots():
        for candidate in candidates:
            path = root / candidate.relative_path
            if path.exists():
                return path
    return None


def _manifest_sdk_candidates() -> Tuple[_SdkDocCandidate, ...]:
    return (
        _SdkDocCandidate("docs/reference/android/Manifest.permission.html"),
        _SdkDocCandidate("docs/offline/android/Manifest.permission.html"),
    )


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
        local_path = _find_sdk_doc(_manifest_sdk_candidates())
        if local_path is not None:
            html = _load_html_from_file(local_path)
            if html:
                return html, f"sdk:{local_path.name}"

    # fallback to online
    html = _fetch_online_html(ONLINE_URL)
    if html:
        return html, "online"
    return None, "unavailable"


def load_additional_permission_doc(url: str) -> Tuple[Optional[str], str]:
    """Fetch an auxiliary permission documentation page."""

    html = _fetch_online_html(url)
    if html:
        return html, "online"
    return None, "unavailable"

