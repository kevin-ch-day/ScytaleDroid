# V1 design note — APK catalog, harvest lineage, install sets, verification (ACK)

**Status:** DRAFT — pending PM/developer ACK  
**Purpose:** Lock naming, semantics, and implementation order **before** DB migrations or cross-repo ingest refactors spread. Tickets should reference this document; do not reopen these choices unless a **test-backed blocker** appears.

**Operational entry (early):** filesystem-only harvest verify: `python -m scytaledroid.DeviceAnalysis.evidence_verify [--data-dir PATH] [--serial SERIAL] [--warnings-as-errors]` (see *Implementation status*).

---

## Scope

Evidence identity, harvest bookkeeping, split-install completeness, filesystem verification (manifest-first), and analysis-run provenance. **Out of scope for this note:** full SQL DDL (follows next), automatic repair tooling, encryption-at-rest.

---

## 1. Table naming and responsibilities

| Table | Role |
| ----- | ----- |
| **`apks`** | Exactly **one row per unique APK content identity** (`sha256` of pulled bytes). Stores hash triple, size, canonical storage pointer, timestamps (e.g. first seen). **Path is mutable storage metadata, not identity.** |
| **`harvest_sessions`** | One row per harvest run (ties device, optional inventory snapshot id, timestamps, coarse session outcome). |
| **`harvest_apk_observations`** | One row **per observation or attempt** in a session: device, package, version from **snapshot**, source path intent, role (base vs split when applicable), **pull outcome**, linkage to **`apk_id` only when bytes were hashed**, errors/warnings. **Not** generic `harvest_items` — name reflects “what harvest saw or did.” |
| **`apk_sets`** | One row per **install/delivery group** for a `(harvest_session, package_name, snapshot-defined cohort)` slice. Carries **`apk_set_id`**, linkage to **`harvest_sessions`**, version fields from snapshot, and **aggregate completeness** (`complete` / `partial` / `failed` / `skipped`). |
| **`apk_set_members`** | Base/split (or singleton) membership: FK to **`apk_set_id`**, expected path(s) / split label from snapshot, **`member_status`**, optional **`apk_id`** when pulled, linkage to **`harvest_apk_observations`** as needed. |

**Supporting detail (policy, not exhaustive column list):** Foreign keys and exact indexes follow in migration work; **this note locks names and meanings**.

---

## 2. Identity rules

- **`sha256`** (actual pulled bytes): **authoritative content identity**.
- **`apk_id`**: stable **relational** primary key into **`apks`**; **globally unique per content hash**.
- **Same bytes ⇒ same `apk_id`.** Re-harvest in a later session ⇒ **new `harvest_apk_observations` (+ lineage)** rows, **not** a new **`apks`** row.
- **`apk_id` is assigned only** after successful pull **and** hash (no bytes ⇒ **no `apk_id`**; session still records skip/failure in **`harvest_apk_observations`** / set members).

**Integrity rule:** conflicting metadata for the same `sha256` (e.g. size / MD5 / SHA1 disagree) ⇒ **fail closed** (corruption signal); no silent merge.

---

## 3. Complete vs partial split groups (V1)

**Technical completeness:** every **PackageManager-reported APK path** for that package **as represented in the inventory snapshot** receives a **terminal member status**.

- **`apk_sets`** is **`complete`** only if **every expected base/split member** was **pulled and hashed** successfully.
- If any expected member ends **`failed`**, **`skipped`** (policy/path), **`missing`**, **`not_pullable`**, etc., aggregate is **`partial`**, **`failed`**, or **`skipped`** according to deterministic rules documented with the migration (failure takes precedence where applicable).

**Static analysis:** may run on **base-only** or partial sets but must propagate **input completeness** (e.g. `split_set_incomplete` / `analysis_input_completeness=base_only`) so reports do not imply a full install corpus.

---

## 4. Snapshot authority

- The **inventory snapshot** bound to the harvest session defines **targets and expected members** for V1.
- **Do not** re-query PackageManager before every artifact pull in V1 (avoids mixed truth mid-session).
- Optional **post-pull drift checks** annotate warnings on observations or members; they **must not silently rewrite** version/package state used for lineage.

---

## 5. Verification CLI (filesystem first)

**Order:** stabilize **`verify --filesystem-only`**, then **DB-backed** verification.

Shared principles:

| Priority | Evidence |
| --------- | --------- |
| 1 | Content hash recomputed from **bytes on disk** |
| 2 | **Harvest manifest / receipt** (what was claimed at harvest time) |
| 3 | **Database row** |
| 4 | **Storage path string** |

- **`verify`:** read-only, report conflicts, **exit non-zero** on integrity breakage (missing files, hash mismatch manifest↔disk, mismatched membership, stray orphans as defined in the verifier spec ticket).
- **Repair:** explicit future command (`repair`); **never** auto-run inside `verify`.

**`verify --filesystem-only`:** ingest manifests/receipts, re-hash artifacts under declared paths, validate expected split membership/counts vs manifests, orphans/missing detection. **Works without MariaDB** (CI/OSS parity).

---

## 6. Analysis provenance (`analysis_runs`)

- Persist **all** outcomes including **`failed`** and **`skipped`** analyses (audit trail ≠ “had findings”).
- Minimum provenance envelope: **`analysis_run_id`**, tool/module name, semver if available, **git SHA + dirty-tree flag**, **profile id**, **schema version**, **config hash**, input **`apk_id` / SHA-256** list, **`status`** (`success` / `partial` / `failed` / `skipped`), **failure stage**, **error summary**, **log artifact path**, timestamp(s). Optional **`analysis_bundle_id`** later; V1 may **derive** a bundle fingerprint from `{tool, git_sha, profile_id, schema_version, config_hash}`.

---

## 7. Findings redaction & fixtures

- **Findings:** **one logical row** with tiered columns (e.g. raw / redacted / normalized, level, **`safe_for_report`**, **`safe_for_publication`**) rather than duplicated rows per tier.
- **Exports:** **redacted by default**; raw permitted in lab DB only by policy.
- **Fixtures:** only **redistributable** APKs/sample blobs in-repo; proprietary or unclear assets **git-ignore** + scripted fetch **or** local-only paths documented.

---

## 8. Implementation order (post-ACK)

1. Catalog **+** observation schema **+** ingest path adjustments (**`apks`**, **`harvest_sessions`**, **`harvest_apk_observations`**).
2. **`apk_sets`**, **`apk_set_members`**, group completeness in harvest write path **and** filesystem manifests.
3. **`verify --filesystem-only`**
4. **`verify`** DB-backed extension
5. **`analysis_runs`** provenance + failed-run persistence hardening

**No migration PR** until this note is **ACKed.**

---

## Implementation status (rolling)

Moves only after PM/dev ACK of this note; treat as “what shipped” vs “design intent.”

| Item | Status |
| ---- | ------ |
| **`verify` filesystem-only (read-only)** | **Shipped:** `python -m scytaledroid.DeviceAnalysis.evidence_verify` — scans `device_apks/**/*.harvest_package_manifest.json`, checks receipt JSON + package name, re-hashes written artifacts when manifest records `sha256`, fails closed on mismatch / missing files. |
| **`harvest_sessions` / observations / `apk_sets` / members** | Not started — requires migration + ingest wiring. |
| **`verify --db`** | Not started. |
| **Explicit `repair` CLI** | Not started. |

---

## ACK

| Role | Name | Date | Signature / note |
|------|------|------|-------------------|
| PM/Product | | | |
| Dev lead | | | |
