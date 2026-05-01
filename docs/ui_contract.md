# ScytaleDroid Terminal UI Contract

This document defines the active terminal UI contract for ScytaleDroid.

The goal is not visual polish. The goal is:

- correctness
- auditability
- operator clarity
- semantic consistency

This contract applies to active CLI paths. Legacy or compatibility renderers may remain in the repo, but they do not define the product model.

## Canonical Terminology

Use these terms in active operator-facing CLI output:

- `Inventory` for device package enumeration
- `Harvest` for APK acquisition
- `Static Analysis Pipeline` for static analysis runs
- `Dynamic Analysis (Cohorts)` for dynamic/runtime runs
- `Evidence` for manifests, receipts, and evidence packs
- `Session` for a run/session identifier
- `Snapshot` for inventory capture state
- `Blocked` for intentional exclusions or policy/capability restrictions

Deprecated user-facing terms:

- `Pull APKs`
- `APK pull`
- `Full analysis`
- `Lightweight scan`
- `Workspace & Evidence`
- `Governance Inputs & Readiness`

## Canonical Status Vocabulary

Use these distinctions in active CLI paths:

### Artifact state
- `present`
- `missing`

### Gate state
- `ready`
- `not ready`

### Execution state
- `clean`
- `partial`
- `failed`

### Capability state
- `enabled`
- `blocked`

Do not use alternate generic UI terms when one of these categories applies.

## Blocked Semantics

`blocked` is a first-class state.

Use it for:

- policy restrictions
- scope exclusions
- intentional skips
- capability-limited actions

Blocked must not be rendered as warning or error by default.

Canonical blocked rendering:

- label: `BLOCKED`
- symbol: `⊘`
- tone: blocked/magenta

## Capability vs Restriction

`non-root` is a device capability state, not a failure state.

Rules:

- `Root: YES | NO | UNKNOWN` expresses capability only
- `NO` on a stock device should be neutral/info, not warning
- if non-root causes a restriction, that restriction should be rendered as `blocked`

## Domain-Specific Exceptions

These terms are accepted domain language, not generic UI state:

- `VALID / INVALID` in dataset/evidence validity contexts
- `GO / NO-GO` in audit verdict contexts

When used, they must be explicitly labeled by domain context, for example:

- `Dataset verdict`
- `Freeze audit result`
- `Freeze capability`

Do not use these as unlabeled generic UI status.

## Rendering Ownership

Rendering ownership for the active CLI:

- `status_messages` -> status lines
- `table_utils` -> tables
- `menu_utils` / `formatter` -> headers, layout blocks, structured sections

This does not require one literal rendering function for every output, but it does require one semantic rendering contract.

## Summary Ownership

Per stage, one practical summary voice should exist:

- Inventory: `DeviceAnalysis/inventory/summary.py`
- Harvest: `DeviceAnalysis/harvest/summary.py`
- Static: `StaticAnalysis/cli/execution/results.py`

Compatibility renderers may remain, but they are not the active contract owners.

## Enforcement

The UI contract is enforced through:

- terminology regression gates
- UI contract tests
- targeted active-path reviews

If a future change introduces a new wording or status model, it should be treated as a contract change, not an incidental edit.

## Palette and Theme Notes

The CLI palette system is a secondary implementation detail under this
contract. It exists to keep the terminal readable, but it does not define the
product model.

Built-in presets currently include:

- `fedora-dark`
- `fedora-light`
- `high-contrast`

Primary environment hints:

1. `SCYTALE_UI_THEME`
2. `SCYTALE_UI_HIGH_CONTRAST`
3. `GTK_THEME`
4. `COLORFGBG`

Implementation ownership:

- palette definitions:
  - `scytaledroid/Utils/DisplayUtils/colors/presets.py`
- runtime detection:
  - `scytaledroid/Utils/DisplayUtils/colors/environment.py`
- registry/helpers:
  - `scytaledroid/Utils/DisplayUtils/colors/palette.py`
- ANSI wrappers:
  - `scytaledroid/Utils/DisplayUtils/colors/ansi.py`

Operational rule:

- palette/theme work should start from the CLI display utilities, not from
  page-level workflow docs or maintenance notes
