# External Reference Enrichment Track

## Purpose

ScytaleDroid already captures strong first-party evidence:

- harvested APK bytes
- static analysis outputs
- dynamic evidence packs
- canonical DB lineage and run identity

The next maturity step is selective **external reference enrichment**. The goal is
not to replace ScytaleDroid evidence, but to add stable outside context that helps
interpret APK behavior at research and publication time.

## Implemented in this pass

### `external_sdk_tracker_intel`

Repo-owned operational table populated from the public Exodus Privacy tracker API:

- source: `https://reports.exodus-privacy.eu.org/api/trackers`
- role: external reference intel
- grain: tracker snapshot rows
- write path: `scripts/db/refresh_external_sdk_tracker_intel.py`
- receipts: `data/state/external_sdk_tracker_intel/`

This table adds:

- tracker name
- code signature hints
- network signature hints
- public documentation links
- tracker categories
- snapshot-date provenance

This is the highest-ROI first external table because it aligns directly with the
static paper’s concern around embedded third-party tracking SDKs while remaining
useful as contextual overlay for dynamic interpretation.

### Current correlation surface

The first read-only correlation surface is:

- `scripts/db/report_external_tracker_context.py`

It correlates `external_sdk_tracker_intel` with selected static endpoint
`root_domain` evidence and intentionally separates:

- specific root overlap
- generic-root overlap
- generic infrastructure overlap

This matters because the current static selected endpoint evidence generally
retains root domains, not full hostnames/URLs. That means the present correlation
layer is useful, but still conservative and often ambiguous for large first-party
or infrastructure domains.

## Why this matters for the papers

### 2025 static paper

The static pipeline already measures manifest, components, permissions, strings,
and MASVS-aligned issues. External tracker intel adds a missing interpretation
layer: when a package exposes tracking-related SDK signatures, ScytaleDroid can
eventually distinguish first-party app logic from embedded third-party collection
and monetization infrastructure.

### 2026 dynamic paper

The dynamic work is evidence-pack-first and baseline-relative. External tracker
intel should remain **context**, not ground truth. It can help explain suspicious
runtime behavior or network deviation without being treated as runtime proof by
itself.

## Next high-value external data gaps

### 1. SDK authority / deprecation context

Likely future table:

- `external_sdk_index_intel`

Candidate source:

- Google Play SDK Index

Value:

- SDK owner/vendor context
- deprecation or policy signals
- public safety / compliance notes

Use:

- distinguish generic SDK presence from SDKs with known policy or ecosystem risk

### 2. App-store metadata context

Likely future table:

- `external_app_store_metadata`

Value:

- store category
- public developer name
- install-band / rating snapshots if legally and operationally safe
- store listing URLs

Use:

- improve publication grouping
- improve category confidence
- compare research cohorts against official store labeling

### 3. Domain / endpoint reference context

Likely future table:

- `external_domain_intel`

Value:

- authoritative ownership labels
- CDN / analytics / ads / crash reporting roles
- public reputation or classification context

Use:

- improve interpretation of static strings and dynamic destinations
- reduce generic-root ambiguity exposed by `report_external_tracker_context.py`
- separate first-party brand domains, infrastructure domains, and likely
  third-party measurement/ads domains more cleanly

### 4. Library / vulnerability context

Likely future table:

- `external_library_vulnerability_intel`

Value:

- vulnerability or advisory overlays for extracted third-party components

Constraint:

- only useful once ScytaleDroid has stable library identity extraction at a
  package/version/vendor grain

## Guardrails

- Keep external reference tables **repo-owned** in the ScytaleDroid operational DB.
- Do **not** write these enrichments into Permission Intel.
- Preserve ScytaleDroid evidence as canonical truth; external data is overlay and
  interpretation support.
- Prefer additive, snapshot-friendly tables with receipts over opaque mutable cache
  blobs.
