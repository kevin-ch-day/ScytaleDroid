# ScytaleDroid Permission Intel Runtime Grants Plan

Status: **REHEARSED — NOT APPLIED TO PRODUCTION**.

The production `scytaledroid_operator` account is unchanged. This plan splits
reference reads, governed submissions, maintenance, and DDL authority instead
of copying that account's broad privileges.

The runtime service account should receive these two roles; its secret remains
in protected configuration and never in Git.

```sql
CREATE ROLE `scytaledroid_pi_reference_reader`;
CREATE ROLE `scytaledroid_pi_governed_submitter`;

GRANT SELECT ON `android_permission_intel`.`android_permission_dict_aosp`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`android_permission_dict_oem`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`android_permission_dict_unknown`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`android_permission_dict_queue`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`android_permission_meta_oem_vendor`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`android_permission_meta_oem_prefix`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`permission_governance_snapshots`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`permission_governance_snapshot_rows`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`permission_signal_catalog`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`permission_signal_mappings`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`permission_cohort_expectations`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`android_permission_v1_catalog_release`
  TO `scytaledroid_pi_reference_reader`;
GRANT SELECT ON `android_permission_intel`.`android_permission_v1_scytaledroid_permission`
  TO `scytaledroid_pi_reference_reader`;

GRANT INSERT ON `android_permission_intel`.`android_permission_dict_queue`
  TO `scytaledroid_pi_governed_submitter`;
GRANT INSERT ON `android_permission_intel`.`android_permission_dict_unknown`
  TO `scytaledroid_pi_governed_submitter`;
GRANT UPDATE (`seen_count`, `last_seen_at_utc`, `triage_status`)
  ON `android_permission_intel`.`android_permission_dict_unknown`
  TO `scytaledroid_pi_governed_submitter`;
GRANT UPDATE (`last_seen_at_utc`)
  ON `android_permission_intel`.`android_permission_dict_oem`
  TO `scytaledroid_pi_governed_submitter`;
```

Neither role receives `CREATE`, `ALTER`, `DROP`, broad `UPDATE`/`DELETE`, repair
executor authority, or any write on `android_permission_obs_sample`.
Maintenance and migrations remain separately approved administrative work.

Two independent restored-database rehearsals proved the listed reference reads
and one synthetic queue submission while DDL, unrelated catalog writes, and an
`obs_sample` insert were denied. The synthetic row, roles, users, credentials,
containers, and data directories were removed after each rehearsal.
