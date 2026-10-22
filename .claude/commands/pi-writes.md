# pi-writes

Read-only PI attribution audit. Verify CURRENT_USER()=claude_ro@<host> and grants;
stop on account mismatch, never switch to systemadmin.
Inspect actual schema columns before querying android_permission_intel.
Per write path report exact SQL, UTC time, counts, latest timestamps and provenance:
unknown dictionary/queue, OEM seen metadata, permission_signal_catalog,
permission_governance_snapshots and permission_governance_snapshot_rows.
Cross-check labels against scytaledroid/Database/db_core/permission_intel.py,
scytaledroid/StaticAnalysis/persistence/permissions_db.py and governance/copy tools.
Queue source_system/requested_by=static-analysis is code-supported attribution.
Unknown/OEM counters and catalog records lack complete writer-event provenance;
separate unattributable totals from proven ScytaleDroid writes.
EREBUS snapshot source identifies authority, not importing client.
Counter increments are encounters, not unique samples/observations.
Never execute intake writers, import, phase-1 copy, migrations or bootstrap.
