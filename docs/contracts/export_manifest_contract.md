# Export Manifest Contract

This contract defines how frozen export artifacts are verified.

## Source of Truth

Baseline manifest path:

`tests/baseline/publication_export_manifest.json`

Changes require:

1. matching drift rationale in `docs/drift/YYYYMMDD_<topic>.md`
2. required reviewers per `CODEOWNERS`

## Frozen Artifact Rules

Only artifacts listed in the manifest are frozen.

For each listed artifact, the manifest records:

1. `path` (relative to export root)
2. `kind`
3. `normalization`
4. `sha256`
5. `size_bytes`

## Normalization Rules

1. `.tex`: `tex_whitespace_lf`
2. all other locked artifacts: `none`

`tex_whitespace_lf` ignores only:

1. spaces/tabs
2. line-ending differences (`CRLF` vs `LF`)

## Comparator Gate

Command:

`scripts/publication/export_manifest_gate.py`

Default compare target:

1. baseline manifest: `tests/baseline/publication_export_manifest.json`
2. artifact root: `output/publication`
3. diff output: `output/audit/comparators/publication_export/<timestamp>/diff.json`

Pass rule:

1. manifest schema valid
2. every listed artifact exists
3. every listed artifact hash/size matches baseline
