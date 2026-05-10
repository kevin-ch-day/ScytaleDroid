# Permission Intel — Classification taxonomy refinement (custom triage vs obfuscation)

**Status:** Design / read-only vocabulary pass. **No schema changes.** **No Scytale `obs_sample` writes.**  
**Goal:** Separate **legitimate custom permissions needing triage** from **unknown / obfuscation / evasion-shaped** strings before S2 observation work.

**Related:** Erebus `docs/data/android_permissions_schema_contract.md`, Scytale [S1.5 classifier contract](permission_intel_scytaledroid_s1_5_classifier_contract.md), [S2 observation design](permission_intel_scytaledroid_s2_observation_design.md).

---

## 1. Problem statement

Today, several distinct **semantic** situations share one **ledger** column (`android_permission_dict_unknown.triage_status`) and one **catch-all** value in producers:

| Semantic idea | Desired treatment |
| --- | --- |
| **Custom triage** | Legitimate app/vendor permission string, plausible namespace, **unresolved** vs dictionaries — needs governance, not malware-by-default. |
| **Unknown / obfuscated** | Random-looking, packed, or generator-shaped token; possible packer/malware habit — **different research signal** than “benign custom.” |
| **Brand spoof candidate** | Looks like OEM/Google/brand space **without** ownership evidence — overlap with suspicious shape but **governance** often differs. |
| **Malformed token** | Syntax/typo/constant misuse — already partially split as `malformed`. |

**Design correction:** “custom needing triage” and “unknown/obfuscation” must not be conflated in documentation, dashboards, or future automation—even if the **physical column** stays `triage_status` until a migration.

---

## 2. Current vocabulary — ScytaleDroid (static → `dict_unknown`)

Source: `StaticAnalysis/persistence/permissions_db.py`.

| `triage_status` | When emitted |
| --- | --- |
| `malformed` | Internal whitespace, malformed prefix list, token fails `_valid_permission_token` (no dot, placeholders, length). |
| `app_defined` | Permission appears in manifest **custom** set and is not resolved as AOSP/OEM earlier. |
| `oem_candidate` | Non-`android.permission.*` and OEM prefix rule match. |
| `aosp_missing` | `android.permission.*` not in AOSP dict. |
| `new` | Non-framework, **no** OEM dict hit, **no** prefix match — **catch-all**. |

**Scytale internal counters** use `"unknown"` for aggregate counts — not a PI `triage_status` (naming collision with research language).

**Conflation risk:** `new` absorbs both **benign unpublished custom** (e.g. `com.bank.mobile.permission.INTERNAL_BROADCAST`) and **obfuscation-like** strings (long random segments, packed subdomains) **unless** additional heuristics are added.

**Partial mitigation today:** `app_defined` separates **declared custom** permissions from the `new` branch — good for static, but VT/malware paths may not have an equivalent “declared custom” signal.

---

## 3. Current vocabulary — Erebus VT ingest (`permission_triage._triage_status`)

Source: `permission_triage._triage_status` (Erebus).

Decision order:

1. `classify_malformed` → **`malformed`**
2. `_is_android_namespace` → **`aosp_missing`**
3. `_is_google_namespace` → **`gms_known`**
4. `resolve_oem_prefixes` → **`oem_candidate`**
5. Else → **`new`**

**Extended triage** values (`malicious_dga`, `brand_spoof`, `suspicious_token`, …) appear in **contract docs**, **reconcile tests**, **research SQL**, and **operator workflows** — they are **not** produced by this single function’s default path; they enter via governance, backfill, or manual update.

**Conflation:** **`new`** is the default bucket for **all non-malformed, non-AOSP-namespace, non-GMS, non-OEM-prefix** strings — exactly where **legitimate custom** and **obfuscated/random** both land.

**Related but separate layer:** `obs_sample` uses **`classification`** (`AOSP`, `GOOGLE`, `OEM`, `APP_DEFINED`, `UNKNOWN`) and **`bucket`/`rule_fired`** — “APP_DEFINED” in obs is **not** the same as `dict_unknown.triage_status = app_defined` (Scytale-only today).

---

## 4. Where “custom,” “unknown,” “new,” and “suspicious” are conflated

| Location | Conflation |
| --- | --- |
| **Erebus `new`** | Single sink for benign custom, suspicious random, and odd third-party namespaces. |
| **Scytale `new`** | Same, minus strings classified earlier as `app_defined` / `oem_candidate`. |
| **Contract doc “unknown ledger”** | Narrative “unknown” mixes **lifecycle state** (row in `dict_unknown`) with **semantic unknown** (unclassified world). |
| **Scytale counter `unknown`** | English “unknown” ≠ PI triage `new` — confuses operators. |
| **`malformed` vs “suspicious”** | `malformed` is **syntax/policy**; **suspicious_token** (research) is **shape/risk** — different axes; both can apply conceptually but only one `triage_status` column today. |
| **`brand_spoof` vs OEM candidate** | `oem_candidate` = prefix match, conservative; `brand_spoof` = governance verdict — not automatically emitted from static/VT triage function. |
| **Research views (`policy_hold`, `suspicious_token`)** | Often **derived** — not the same as persisting a new `triage_status` per string at ingest. |

---

## 5. Proposed semantic buckets (design layer)

These are **logical buckets** for docs, reports, and future LUT/enum — **not** a commitment to immediate DDL.

| Proposed bucket | Meaning |
| --- | --- |
| `aosp_known` | In `dict_aosp` (reference truth). |
| `gms_known` | Google/GMS namespace / policy (aligns with `gms_known` triage where used). |
| `oem_known` | In `dict_oem` (confirmed vendor). |
| `app_defined` | Legitimate application-defined permission (manifest or strong producer signal). |
| `custom_triage` | **Legitimate-looking custom, unresolved** — should not default to malware framing. |
| `unknown_obfuscated` | **High entropy / packed / generator-shaped** — malware-research signal. |
| `brand_spoof_candidate` | Brand-like namespace **without** ownership evidence. |
| `malformed_token` | Aligns with current **`malformed`**. |
| `suspicious_token` | Shape/heuristic tag (may stay **derived** before becoming triage). |
| `policy_hold` | Governance/research hold (often **view-derived** or manual). |

---

## 6. Mapping table: current → proposed semantics

| Current value / signal | Proposed semantic bucket(s) | Likely producers | Promotion path | Safe for automatic classification? |
| --- | --- | --- | --- | --- |
| `malformed` | `malformed_token` | Erebus, Scytale | Fix string or reject; rarely promote to dict | **High** for labeling; **low** for auto-dict promotion |
| `aosp_missing` | `aosp_known` (after queue promote) or stay intake | Erebus, Scytale | Queue → AOSP dict | Medium (human/queue) |
| `gms_known` | `gms_known` | Erebus | Optional dict enrichment | Medium |
| `oem_candidate` | `oem_known` after confirmation; else stays candidate | Erebus, Scytale | Queue → OEM dict; vendor linkage | Low without human |
| Scytale `app_defined` | `app_defined` / `custom_triage` | Scytale static | Resolve to OEM/AOSP alias or accept as app-defined | Medium (producer knows manifest) |
| **`new`** (Erebus/Scytale) | **Split:** `custom_triage` **or** `unknown_obfuscated` (+ optional `brand_spoof_candidate`) | Both | Heuristics → triage update; or research-only tag | **Low** until split rules exist |
| `resolved_aosp` / `resolved_oem` | Terminal resolved | Ops | N/A | N/A |
| `malicious_dga` (governance) | `unknown_obfuscated` family | Ops/reconcile | Research + possible dict ban | Low |
| `brand_spoof` (governance) | `brand_spoof_candidate` confirmed | Ops | Separate from OEM dict | Low |
| `suspicious_token` (SQL/views) | `suspicious_token` (derived or future triage) | Analytics | Feed back to triage optionally | Medium as **tag**, low as sole triage |
| `policy_hold` | `policy_hold` | Research pipeline | Manual / SP | Low |
| `obs_sample.APP_DEFINED` | Coarse ingest class | Erebus | Not equal to `dict_unknown.app_defined` | N/A |
| `obs_sample.UNKNOWN` + `OEM_CANDIDATE` bucket | OEM prefix candidate (Erebus contract) | Erebus | Align language with `oem_candidate` triage | Medium |

---

## 7. Answers to design questions

### Should `new` be split logically into `custom_triage` and `unknown_obfuscated`?

**Yes, logically.** Physically, options are: (a) two new `triage_status` values after LUT migration, (b) keep `new` and add a **second column or sidecar** (risk tag / research flag), (c) **derived bucket only** in views (lowest risk first).

### Should `unknown_obfuscated` be a new `triage_status`, a risk tag, or a derived report bucket?

**Lowest-risk path:** **derived report bucket** (view or batch scorer) keyed on `permission_string` + heuristics, **without** changing ingest yet.  
**Medium:** optional **`notes` / JSON** extension (if schema allows) before new ENUM values.  
**High coordination:** new `triage_status` + LUT FK (requires Erebus + Scytale + DBA).

### Should brand spoof remain separate from suspicious token?

**Yes.** Brand spoof is **namespace ownership / impersonation**; suspicious token is **shape/entropy**. A string can be both; governance should allow **orthogonal tags** or **precedence rules** documented explicitly.

### How should Scytale classify legitimate Play Store app-defined permissions without malware-like framing?

Use **producer context:** manifest-declared custom → prefer **`app_defined`** (already). For non-declared uses-only strings, prefer **neutral `custom_triage`** semantics in reporting once split; avoid labeling “unknown = malicious.”

### How should Erebus classify random/generated strings without polluting custom triage?

Do **not** overload `new` in dashboards: add **entropy/length/pattern scorer** → `unknown_obfuscated` **derived** cohort; only promote to persisted triage after review or automated policy with **tunable thresholds**.

### Lowest-risk path?

1. **Docs + report SQL / views** (derived buckets).  
2. **Operator playbook** for manual recoding of high-value subsets.  
3. **LUT / ENUM** only after volume + false-positive study.

---

## 8. Recommended tests (future / optional)

| Test | Purpose |
| --- | --- |
| Scytale: keep [triage vocabulary contract](permission_intel_scytaledroid_s1_5_classifier_contract.md) | Ensures emitted statuses stay in PI-allowed set. |
| **New:** design-sketch examples (`test_permission_intel_custom_vs_obfuscated_design_sketch.py`) | Prevents accidental deletion of semantic examples; extend when rules exist. |
| Erebus: extend `permission_triage` unit tests when `custom_triage` / `unknown_obfuscated` rules land | Golden strings per bucket. |
| Cross-repo: LUT snapshot test when DDL adds ENUM values | Prevent drift. |

---

## 9. Deliverables summary

| Artifact | Location |
| --- | --- |
| This design note | `docs/database/permission_intel_classification_taxonomy_refinement.md` |
| Example strings (test) | `tests/database/test_permission_intel_custom_vs_obfuscated_design_sketch.py` |

**Next step (low risk):** Adopt **derived cohorts** in analytics (entropy/pattern + manifest context), document in Erebus research runbook / Scytale ops doc; **defer** `triage_status` ENUM change until cohort quality is validated.

---

## 10. Cross-links for Erebus maintainers

When extending ENUM/LUT, update:

- `docs/data/android_permissions_schema_contract.md` (ledger narrative)
- `permission_triage._triage_status` and unknown upsert CASE
- Scytale `permissions_db.py` and `tests/database/test_permission_intel_triage_vocabulary_contract.py`
