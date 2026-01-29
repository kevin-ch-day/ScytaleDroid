"""Load and validate dynamic analysis plans."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple


def load_dynamic_plan(path: str | Path) -> Dict[str, Any]:
    plan_path = Path(path)
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("dynamic plan payload must be an object")
    return data


def validate_dynamic_plan(
    plan: Dict[str, Any],
    *,
    package_name: str,
    static_run_id: int | None = None,
) -> Tuple[bool, str | None]:
    plan_package = plan.get("package_name")
    if plan_package and plan_package != package_name:
        return False, f"plan package mismatch (plan={plan_package} target={package_name})"
    if static_run_id is not None:
        plan_run_id = plan.get("static_run_id")
        if plan_run_id is None:
            return False, "plan missing static_run_id"
        try:
            if int(plan_run_id) != int(static_run_id):
                return False, f"plan static_run_id mismatch (plan={plan_run_id} target={static_run_id})"
        except (TypeError, ValueError):
            return False, f"plan static_run_id invalid (plan={plan_run_id})"
    return True, None


__all__ = ["load_dynamic_plan", "validate_dynamic_plan"]
