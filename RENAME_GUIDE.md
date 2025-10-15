Renaming & Module Naming Guide
==============================

Purpose: Improve discoverability by switching from terse file names to
descriptive module names. Legacy modules remain as thin shims to avoid
breaking existing imports.

StaticAnalysis / Permissions
---------------------------

- analysis/scoring.py → analysis/risk_scoring_engine.py (re-exported)
- analysis/signals.py → analysis/capability_signal_classifier.py (re-exported)
- simple.py → permissions_rendering_core.py (re-exported)
- render_postcard.py, render_matrix.py, render_summary.py (new descriptive entrypoints)

AndroidPermCatalog
------------------

- api.py → permissions_catalog_api.py (re-exported)
- ops.py → permissions_catalog_operations.py (re-exported)
- loader.py → permissions_catalog_loader.py (re-exported)
- menu.py → permissions_catalog_menu.py (re-exported)

Notes
-----

- All shims re-export the legacy APIs. New code should import from the
  descriptive modules. Existing code stays functional.
- Future phases can complete the rename by updating all imports and
  removing the shims after a deprecation window.

