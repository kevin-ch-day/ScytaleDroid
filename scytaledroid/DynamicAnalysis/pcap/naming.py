"""Stable PCAP capture naming helpers."""

from __future__ import annotations

import re

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def package_slug(package_name: str | None) -> str:
    text = str(package_name or "").strip().lower()
    slug = _NON_ALNUM_RE.sub("_", text).strip("_")
    return slug or "unknown_app"


def make_pcap_capture_name(package_name: str | None, dynamic_run_id: str, *, ext: str = "pcap") -> str:
    slug = package_slug(package_name)
    run_id = str(dynamic_run_id or "").strip() or "unknown_run"
    suffix = str(ext or "pcap").strip().lstrip(".") or "pcap"
    return f"scytaledroid_{slug}_{run_id}.{suffix}"


__all__ = ["make_pcap_capture_name", "package_slug"]
