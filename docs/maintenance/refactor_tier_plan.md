# Refactor Tier Plan

This document captures a staged refactor order to keep changes bounded and behavior-preserving.

## Tier 1 — Best ROI, lower risk

Start here:

- `scytaledroid/Database/db_utils/menus/health_checks.py`
- `scytaledroid/Database/db_utils/menu_actions.py`
- `scytaledroid/Reporting/menu_actions.py`
- `scytaledroid/StaticAnalysis/cli/views/renderers/summary_render.py`
- `scytaledroid/DeviceAnalysis/harvest/summary.py`

Rationale:

- These modules are menu/rendering/summary heavy and are often easier to split without changing research behavior.
- They likely mix presentation with status/summary calculation, which can be separated with helper extraction.
- Behavior can usually be preserved with targeted tests.
- This is lower risk than dynamic-analysis ML/evidence-pack core logic.

## Tier 2 — Medium risk, high value

After Tier 1 patterns are stable:

- `scytaledroid/StaticAnalysis/cli/execution/results.py`
- `scytaledroid/StaticAnalysis/cli/persistence/run_summary.py`
- `scytaledroid/StaticAnalysis/cli/flows/run_dispatch.py`
- `scytaledroid/Reporting/services/publication_exports_service.py`
- `scytaledroid/Database/db_queries/views_web.py`

Rationale:

- High-value cleanup targets.
- Closer to persistence/report contracts, DB read models, and output semantics.
- Requires bounded, compatibility-preserving refactors.

## Tier 3 — Highest risk, defer

Defer until lower-risk cleanup patterns are proven and repeatable:

- `scytaledroid/DynamicAnalysis/ml/evidence_pack_ml_orchestrator.py`
- `scytaledroid/DynamicAnalysis/ml/artifact_bundle_writer.py`
- `scytaledroid/DynamicAnalysis/menu.py`
- `scytaledroid/DynamicAnalysis/core/orchestrator.py`
- `scytaledroid/DynamicAnalysis/controllers/guided_run.py`
- `scytaledroid/DynamicAnalysis/scenarios/manual.py`
- `scytaledroid/DynamicAnalysis/ml/query_mode_runner.py`
- `scytaledroid/DynamicAnalysis/pcap/dataset_tracker.py`

Rationale:

- These modules are likely tied to dynamic-analysis research behavior and evidence contracts.
- Changes can impact evidence packs, RDI outputs, readiness/freeze checks, ML artifacts, and reproducibility.
- Tackle only after Tier 1 and Tier 2 extraction patterns are stable.
