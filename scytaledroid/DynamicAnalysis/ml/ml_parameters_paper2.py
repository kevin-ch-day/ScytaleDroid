"""Compatibility shim for the former `ml_parameters_paper2.py` module.

OSS posture:
- Canonical config lives in `ml_parameters_profile.py`.
- This module remains for one major cycle to avoid breaking older tooling.
"""

from __future__ import annotations

# Re-export the canonical profile parameters without adding import-time warnings.
from .ml_parameters_profile import *  # noqa: F403

