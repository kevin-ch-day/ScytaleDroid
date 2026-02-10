"""Identity and deterministic seeding helpers for Paper #2 ML."""

from __future__ import annotations

import hashlib
from typing import Any

from . import ml_parameters_paper2 as config


def identity_key_from_plan(plan: dict[str, Any] | None) -> str | None:
    """Return the deterministic identity key for grouping runs (preferred source)."""
    if not isinstance(plan, dict):
        return None
    ident = plan.get("run_identity")
    if not isinstance(ident, dict):
        return None
    fields = (
        ident.get("run_signature_version"),
        ident.get("run_signature"),
        ident.get("artifact_set_hash"),
        ident.get("base_apk_sha256"),
    )
    if all(isinstance(x, str) and x for x in fields):
        return ":".join(fields)  # stable join key
    return None


def identity_key_fallback(manifest: dict[str, Any] | None) -> str | None:
    """Fallback identity key if plan identity is missing (should be rare)."""
    if not isinstance(manifest, dict):
        return None
    target = manifest.get("target") or {}
    if not isinstance(target, dict):
        return None
    pkg = target.get("package_name")
    static_run_id = target.get("static_run_id")
    if isinstance(pkg, str) and pkg:
        return f"{pkg}:static_run_id={static_run_id}"
    return None


def derive_seed(identity_key: str) -> int:
    """Derive a stable 32-bit seed from identity key + fixed salt."""
    token = f"{identity_key}|{config.SEED_SALT}".encode()
    digest = hashlib.sha256(token).hexdigest()
    # 32-bit seed range for sklearn random_state.
    return int(digest[:8], 16)


def salt_metadata() -> dict[str, str]:
    return {"salt_label": config.SEED_SALT_LABEL}
