# Static Persistence UoW Tables

This document locks the scientific unit-of-work (UoW) table scope for
`persist_run_summary`.

## Scientific UoW Tables

These tables are considered scientific output and must obey:

1. atomic commit semantics
2. zero scientific rows on failure
3. rollback proof checks in tests/audit SQL

Current scientific table set:

1. `apps`
2. `app_versions`
3. `static_analysis_runs`
4. `static_analysis_findings`
5. `static_correlation_results`
6. `static_fileproviders`
7. `static_provider_acl`
8. `risk_scores`
9. `static_permission_risk_vnext`
10. `static_permission_matrix`
11. `masvs_control_coverage`
12. `static_findings_summary`
13. `static_findings`
14. `static_string_summary`
15. `static_string_samples`
16. `static_string_selected_samples`
17. `static_string_sample_sets`
18. `doc_hosts`
19. `static_finding_evidence_payloads`

## Ledger / Audit Tables (Non-Scientific)

These tables may be written on failure paths for traceability and are not part
of the scientific output set:

1. `static_persistence_failures`

## Status Contract

Authoritative scientific statuses:

1. `STARTED`
2. `COMPLETED`
3. `FAILED`

Legacy status tokens must map to authoritative values before persistence.
