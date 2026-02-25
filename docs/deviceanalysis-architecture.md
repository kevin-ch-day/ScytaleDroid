# DeviceAnalysis Architecture Contract (Status Matrix)

Note: This document tracks a legacy internal migration plan for the DeviceAnalysis package.
It is not the active implementation plan. Legacy paper export/repro notes are
kept under `docs/legacy/paper2/` as an optional reference path.

## Layering rules
- **UI-only printing/prompting:** Any `print()`, prompts, panels, or progress UI must live in the UI layer.
- **ADB-only shell calls:** Any ADB command construction, shell calls, or ADB parsing must live in `DeviceAnalysis/adb/`.
- **Workflows-only orchestration:** Any flow that coordinates inventory + harvest + UI decisions must live in `DeviceAnalysis/workflows/`.

## Allowed import matrix
| Layer/Package | Allowed to import |
| --- | --- |
| `DeviceAnalysis/adb/` | stdlib only |
| `DeviceAnalysis/inventory/` | `adb/` + stdlib |
| `DeviceAnalysis/harvest/` | `adb/` + stdlib |
| `DeviceAnalysis/workflows/` | `adb/`, `inventory/`, `harvest/`, `services/`, `ui/` |
| `DeviceAnalysis/services/` | `adb/`, `inventory/`, `harvest/` |
| `DeviceAnalysis/ui/` (and `device_menu/`) | `workflows/`, `services/` |

**UI boundary:** UI must not import `adb/`, `inventory/`, or `harvest/` directly.

## Root module rule
No new modules should be added at the `DeviceAnalysis/` root. New work must go into one of the approved packages:
- `adb/`
- `inventory/`
- `harvest/`
- `workflows/`
- `services/`
- `ui/` (or `device_menu/` while migration is in progress)

Legacy root files should be treated as compatibility shims until migrated.

## Migration tracker (legacy status, not current sprint)
| Phase | Scope | Status |
| --- | --- | --- |
| Phase 0 | Architecture contract + import rules | **In progress** |
| Phase 1 | Canonical ADB layer + shims | **In progress** |
| Phase 2 | Workflows package + orchestration move | **In progress** |
| Phase 3 | UI consolidation into `ui/` | **Not started** |
| Phase 4 | Remove duplicate inventory ADB | **Not started** |
| Phase 5 | Minimal tests (delta, planner, workflow smoke) | **Not started** |

### Phase 2 checklist
- [ ] `workflows/` package exists
- [ ] `workflows/apk_pull_workflow.py` wrapper created
- [ ] UI/menu calls workflows wrapper for APK pull
- [ ] No new orchestration added in UI or root files
- [ ] Phase 2 manual verification steps completed
