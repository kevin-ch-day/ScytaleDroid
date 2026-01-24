"""Load and validate dynamic analysis plans."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


def load_dynamic_plan(path: str | Path) -> Dict[str, Any]:
    plan_path = Path(path)
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("dynamic plan payload must be an object")
    return data

