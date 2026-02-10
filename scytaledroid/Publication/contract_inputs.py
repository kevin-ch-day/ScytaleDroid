"""Canonical publication contracts (display aliases + ordering).

Design goals:
- Contracts must be available on a fresh checkout (no dependence on gitignored `data/`).
- Contracts may be overridden at runtime (e.g., for a specific bundle snapshot).
- Regeneration/gates may treat missing contracts as a hard failure (fail-closed),
  but interactive tooling may choose fail-open.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from scytaledroid.Config import app_config


@dataclass(frozen=True)
class PublicationContracts:
    display_name_by_package: dict[str, str]
    package_order: list[str]


def _repo_contracts_dir() -> Path:
    # Tracked defaults live next to this module.
    return Path(__file__).resolve().parent / "contracts"


def _archive_dir() -> Path:
    return Path(app_config.DATA_DIR) / "archive"


def _contract_dir_candidates() -> list[Path]:
    """Search order for contract directory."""
    out: list[Path] = []
    # Preferred generic knob.
    env = os.environ.get("SCYTALEDROID_CONTRACT_DIR", "").strip()
    if env:
        out.append(Path(env))
    # Back-compat for older environments.
    legacy = os.environ.get("SCYTALEDROID_PAPER_CONTRACT_DIR", "").strip()
    if legacy:
        out.append(Path(legacy))
    # Prefer tracked defaults so fresh checkouts work.
    out.append(_repo_contracts_dir())
    # Allow overrides under data/archive for local pinned snapshots.
    out.append(_archive_dir())
    return out


def display_name_map_path() -> Path:
    for d in _contract_dir_candidates():
        p = d / "display_name_map.json"
        if p.exists():
            return p
    # Default fallback (for error message paths).
    return _repo_contracts_dir() / "display_name_map.json"


def app_ordering_path() -> Path:
    for d in _contract_dir_candidates():
        p = d / "app_ordering.json"
        if p.exists():
            return p
        # Back-compat for legacy filename.
        p_legacy = d / "paper_ordering.json"
        if p_legacy.exists():
            return p_legacy
    return _repo_contracts_dir() / "app_ordering.json"


def load_publication_contracts(*, fail_closed: bool = True) -> PublicationContracts:
    """Load canonical publication contracts.

    If fail_closed=True, missing/invalid files raise RuntimeError (fail-closed posture).
    """

    dn_path = display_name_map_path()
    ord_path = app_ordering_path()

    def die(msg: str) -> None:
        if fail_closed:
            raise RuntimeError(msg)

    if not dn_path.exists():
        die(f"Missing display name map: {dn_path}")
        return PublicationContracts(display_name_by_package={}, package_order=[])
    if not ord_path.exists():
        die(f"Missing app ordering: {ord_path}")
        return PublicationContracts(display_name_by_package={}, package_order=[])

    try:
        dn = json.loads(dn_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        die(f"Failed to read display name map: {dn_path} ({exc})")
        dn = {}
    if not isinstance(dn, dict):
        die(f"Invalid display name map (expected object): {dn_path}")
        dn = {}
    display: dict[str, str] = {}
    for k, v in dn.items():
        pkg = str(k).strip()
        name = str(v).strip()
        if pkg and name:
            display[pkg] = name

    try:
        order_obj = json.loads(ord_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        die(f"Failed to read app ordering: {ord_path} ({exc})")
        order_obj = []
    if not isinstance(order_obj, list):
        die(f"Invalid app ordering (expected array): {ord_path}")
        order_obj = []
    order = [str(x).strip() for x in order_obj if str(x).strip()]

    # Minimal sanity: order must not contain duplicates.
    seen = set()
    dups = [p for p in order if (p in seen) or seen.add(p)]
    if dups:
        die(f"app_ordering contains duplicate entries: {sorted(set(dups))}")

    return PublicationContracts(display_name_by_package=display, package_order=order)


def canonical_display_name(pkg: str, *, contracts: PublicationContracts) -> str:
    return contracts.display_name_by_package.get(pkg, pkg)
