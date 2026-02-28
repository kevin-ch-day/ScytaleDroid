# Operator Golden Paths

This document defines the boring, repeatable workflows that are expected to work
on any OSS checkout. If you need to demo, reproduce paper artifacts, or debug
readiness, start here.

## Profile v2 (FROZEN) (Paper #2 archival)

Goal: reproduce the archived Paper #2 outputs from the frozen 12-app cohort.

1. Launch TUI:
   - `./run.sh`
1. Reporting:
   - Reporting -> Profile v2 (FROZEN)
1. Generate artifacts + bundle:
   - "Regenerate v2 artifacts (Frozen 12-app cohort)"
   - "Write v2 canonical publication bundle (output/publication/)"
1. Lint:
   - "Lint v2 publication bundle (PASS/FAIL)"

Batch equivalent:

```bash
scripts/operator/run_profile_v2_demo.sh
```

Outputs:
- `output/publication/` (canonical v2 bundle surface)

## Profile v3 (STRUCTURAL) (Paper #3)

Goal: run integrity gates, export Profile v3 structural artifacts, and lint READY.

Paper-grade order (do not deviate):

1. Sync device inventory (mandatory for v3)
1. Install all cohort apps on device (Drive/Sheets included)
1. Freeze catalog to exactly 21 apps:
   - `profiles/profile_v3_app_catalog.json`
1. Pull APKs using the v3 scope (full refresh)
1. Run v3 integrity gates (catalog freeze + freshness + scripted coverage)
1. Capture scripted dynamic runs
1. Build `data/archive/profile_v3_manifest.json`
1. Export + lint (strict mode for paper/demo)

Batch equivalent:

```bash
scripts/operator/run_profile_v3_demo.sh
```

Gate runner (prints a one-screen PASS/FAIL summary):

```bash
scripts/profile_tools/profile_v3_integrity_gates.py
```

Outputs:
- `output/publication/profile_v3/` (publication-facing v3 artifacts)
- `output/experimental/profile_v3/` (exploratory clustering artifacts)

