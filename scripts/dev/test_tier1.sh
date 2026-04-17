#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

pytest -q "$@" \
  tests/unit \
  tests/utils \
  tests/inventory \
  scytaledroid/StaticAnalysis/modules/string_analysis/tests \
  tests/device_analysis/test_device_dashboard.py \
  tests/device_analysis/test_inventory_progress.py \
  tests/device_analysis/test_inventory_sync_menu.py \
  tests/harvest/test_harvest_summary.py \
  tests/dynamic/test_dataset_run_state_service.py \
  tests/dynamic/test_guided_run_state_integration.py \
  tests/dynamic/test_menu_next_action.py \
  tests/dynamic/test_menu_evidence_quota.py \
  tests/static_analysis/test_results_persistence.py \
  tests/static_analysis/test_results_noncanonical_output.py \
  tests/static_analysis/test_governance_gating.py \
  tests/static_analysis/test_run_dispatch_linkage_order.py \
  tests/gates/test_phase1_ui_contract.py \
  tests/gates/test_no_user_facing_legacy_mode_terms.py
