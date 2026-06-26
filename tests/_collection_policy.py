from __future__ import annotations

from pathlib import Path


def derived_markers_for_path(rel_path: str | Path) -> tuple[str, ...]:
    path = Path(rel_path)
    parts = path.parts
    if not parts:
        return ()

    if parts[0] == "tests":
        parts = parts[1:]
    if len(parts) < 2:
        return ()

    bucket = parts[0]
    filename = parts[-1]

    markers: list[str] = []
    if bucket == "gates":
        markers.extend(("contract", "gate"))
    elif bucket == "ui":
        markers.extend(("contract", "ui_contract"))
    elif bucket == "unit":
        markers.append("unit")
    elif bucket == "integration":
        markers.append("integration")

    if bucket == "db" and filename.startswith("test_report_"):
        markers.append("report_contract")

    seen: set[str] = set()
    ordered: list[str] = []
    for marker in markers:
        if marker in seen:
            continue
        seen.add(marker)
        ordered.append(marker)
    return tuple(ordered)
