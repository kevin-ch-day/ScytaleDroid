# PM Update (Branchless-Friendly): Test/Legacy Cleanup Progress

**Date:** 2026-04-13  
**Audience:** Project management and stakeholders without branch/code access  
**Purpose:** Explain what changed, why it matters, and what is next in plain operational terms.

## 1) Executive Summary

We are executing a controlled cleanup to reduce legacy surface area while preserving current production contracts.

What is done so far:

- Stabilized test execution around API test-client dependency behavior.
- Reduced duplicated test boilerplate via shared helper extraction.
- Updated several tests to match current schema/contract expectations.
- Produced two planning artifacts so cleanup can be tracked as bounded work (not open-ended refactor).

Net effect so far:

- Full suite remains healthy in this environment: **563 passed, 9 skipped**.
- We now have an explicit removal/consolidation roadmap with risk tiers and sequencing.

## 2) What Was Wrong Before

Before this cleanup wave, the team had three main maintainability issues:

1. **Legacy compatibility drag:** Scripts/tests still contained transition-era code paths and aliases.
2. **Duplicated test setup:** API tests repeated optional dependency checks in multiple places.
3. **Contract drift risk:** A few tests reflected older schema/constructor assumptions and were brittle.

This meant that each future cleanup would cost more than necessary and increase review burden.

## 3) What Changed (Plain-English)

### A) API test setup centralized

- A single helper now handles optional API test-client dependency checks.
- API tests call that helper instead of duplicating import/skip logic.

Why PM should care:

- Fewer moving parts in tests.
- Faster/safer updates when dependency behavior changes.
- Lower chance of inconsistent test behavior between environments.

### B) Legacy/prune planning made concrete

Two structured plans are now in repo:

- **Testing prune plan:** what test groups are candidates for removal vs consolidation.
- **Batch-2 script prune plan:** which scripts can be pruned first, with risk levels and execution criteria.

Why PM should care:

- Cleanup is now trackable and schedulable.
- Decisions are tied to prerequisites and “done” conditions.
- Prevents accidental deletion of protections that still enforce current contracts.

### C) Test alignment with current contracts

- Targeted updates were made where tests were out of sync with current data model/schema behavior.
- This reduces false failures that do not represent product regressions.

Why PM should care:

- CI failures become more meaningful.
- Engineers spend less time on noise and more on actual defects.

## 4) What Has NOT Changed

To reduce risk, this work intentionally did **not** change core runtime behavior.

- No production workflow semantics were rewritten.
- No canonical contract checks were intentionally removed.
- No high-signal safety tests (offline gates, transaction atomicity, subprocess boundary checks) were removed.

## 5) Why Some Tests Skip

You may see some API tests marked "skipped" in environments missing optional test dependencies.

This is expected and controlled behavior:

- If optional client dependency is not installed, those tests skip instead of hard-failing the suite.
- In environments with dependency installed, they execute normally.

This makes CI behavior predictable across heterogeneous environments while preserving coverage where supported.

## 6) Risk Management Approach

We are following a conservative cleanup policy:

1. Remove only low-risk wrappers first.
2. Consolidate overlapping scripts/tests before deleting protections.
3. Keep canonical output paths and contract guards intact.
4. Tie each prune candidate to objective checks (call-site search, test pass, runbook updates).

## 7) Next Planned Work (Small / Medium / Medium)

### Next PR-A (Small)

- Remove low-risk, legacy/demo wrappers with zero references.
- Update runbook references.

**Expected impact:** immediate reduction in confusion and surface area with low regression risk.

### Next PR-B (Medium)

- Merge profile preflight scripts into one orchestrator CLI with subcommands.

**Expected impact:** less script sprawl; easier onboarding and support.

### Next PR-C (Medium)

- Remove duplicate publication alias writes after deprecation window.
- Keep canonical output paths only.

**Expected impact:** lower output drift risk and simpler validation.

## 8) PM Tracking Checklist

Use this checklist for governance:

- [ ] Candidate has no active call sites.
- [ ] Replacement path is documented and tested.
- [ ] Canonical contract coverage remains intact.
- [ ] CI/test baseline unchanged or improved post-change.
- [ ] Runbook/docs updated for user-facing behavior.

---

If helpful, I can provide the next update in a one-page “status delta” format (what changed this week, what was removed, what risk was retired, and what remains).
