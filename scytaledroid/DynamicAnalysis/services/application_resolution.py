"""Application discovery for capture; matching does not establish build identity."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher


@dataclass(frozen=True)
class Application:
    package: str
    label: str
    installed: bool | None = None
    harvested: bool = False
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class Matches:
    applications: tuple[Application, ...]
    fuzzy: bool = False


def merge_applications(installed, catalog, harvested) -> list[Application]:
    """Merge by exact package ID, never by a possibly shared display label."""
    labels = dict(harvested)
    labels.update({p: label for p, label in catalog.items() if label})
    packages = set(labels) | set(installed or ()) | set(harvested)
    known_aliases = {"com.zhiliaoapp.musically": ("TikTok",)}
    return [
        Application(
            p,
            labels.get(p) or p,
            p in installed if installed is not None else None,
            p in harvested,
            known_aliases.get(p, ()),
        )
        for p in sorted(packages)
    ]


def find_applications(query: str, applications: list[Application]) -> Matches:
    needle = query.strip().casefold()
    if not needle:
        return Matches(())
    exact_package = [a for a in applications if a.package.casefold() == needle]
    if exact_package:
        return Matches(tuple(exact_package))

    def names(a):
        return [a.label.casefold(), a.package.casefold(), *(s.casefold() for s in a.aliases)]

    exact = [a for a in applications if needle in names(a)]
    if exact:
        return Matches(tuple(exact))
    partial = [a for a in applications if any(needle in n for n in names(a))]
    if partial:
        return Matches(tuple(partial))
    if len(needle) < 4:
        return Matches(())
    scored = [
        (max(SequenceMatcher(None, needle, n).ratio() for n in names(a)), a) for a in applications
    ]
    plausible = sorted(
        ((score, a) for score, a in scored if score >= 0.80),
        key=lambda pair: (-pair[0], pair[1].package),
    )
    return Matches(tuple(a for _, a in plausible), fuzzy=bool(plausible))


def load_applications(serial: str) -> tuple[list[Application], list[str]]:
    from scytaledroid.Database.db_core import db_queries
    from scytaledroid.DeviceAnalysis.package_inventory import list_packages
    from scytaledroid.StaticAnalysis.core.repository import group_artifacts
    from scytaledroid.StaticAnalysis.core.repository import list_packages as harvested_packages

    notes = []
    try:
        installed = set(list_packages(serial)) or None
    except Exception:
        installed = None
    if installed is None:
        notes.append("Installed-app listing unavailable; selected app will be checked directly.")
    try:
        rows = db_queries.run_sql("SELECT package_name, display_name FROM apps", fetch="all_dict")
        catalog = {r["package_name"]: r.get("display_name") for r in rows or []}
    except Exception:
        catalog = {}
        notes.append("Application catalog unavailable; searching other sources.")
    try:
        harvested = {
            p: label for p, _version, _count, label in harvested_packages(group_artifacts())
        }
    except Exception:
        harvested = {}
        notes.append("Harvest inventory unavailable; searching other sources.")
    return merge_applications(installed, catalog, harvested), notes
