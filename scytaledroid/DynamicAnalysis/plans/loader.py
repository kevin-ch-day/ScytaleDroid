"""Stable public facade for dynamic plan loading and validation."""

from __future__ import annotations

from scytaledroid.Database.db_core import DatabaseError, db_queries as core_q

from .models import (
    PlanValidationError,
    PlanValidationOutcome,
    SUPPORTED_PLAN_SCHEMA_VERSIONS,
    SUPPORTED_SIGNATURE_VERSIONS,
)
from .payload import enrich_dynamic_plan, extract_plan_identity, load_dynamic_plan
from .rendering import (
    build_plan_validation_event,
    plan_validation_pass_message,
    render_plan_validation_block,
)
from .validation import validate_dynamic_plan


__all__ = [
    "PlanValidationError",
    "PlanValidationOutcome",
    "SUPPORTED_SIGNATURE_VERSIONS",
    "extract_plan_identity",
    "build_plan_validation_event",
    "enrich_dynamic_plan",
    "load_dynamic_plan",
    "plan_validation_pass_message",
    "render_plan_validation_block",
    "validate_dynamic_plan",
]
