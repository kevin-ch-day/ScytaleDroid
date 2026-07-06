from __future__ import annotations

from scytaledroid.DynamicAnalysis import plans
from scytaledroid.DynamicAnalysis.plans import loader


def test_plans_package_re_exports_loader_surface() -> None:
    assert plans.PlanValidationOutcome is loader.PlanValidationOutcome
    assert plans.PlanValidationError is loader.PlanValidationError
    assert plans.load_dynamic_plan is loader.load_dynamic_plan
    assert plans.enrich_dynamic_plan is loader.enrich_dynamic_plan
    assert plans.extract_plan_identity is loader.extract_plan_identity
    assert plans.validate_dynamic_plan is loader.validate_dynamic_plan
    assert plans.render_plan_validation_block is loader.render_plan_validation_block
    assert plans.build_plan_validation_event is loader.build_plan_validation_event
    assert plans.SUPPORTED_SIGNATURE_VERSIONS is loader.SUPPORTED_SIGNATURE_VERSIONS
    assert plans.SUPPORTED_PLAN_SCHEMA_VERSIONS is loader.SUPPORTED_PLAN_SCHEMA_VERSIONS
