#!/usr/bin/env python3
"""Preview the unapplied 0.3.17 install-set identity migration.

Production application is intentionally not exposed by this source-only work package.
"""
from __future__ import annotations
import json
from scytaledroid.Database.db_utils.install_set_hash_version_propagation import DDL, MIGRATION_ID, SCHEMA_VERSION_AFTER

def main() -> int:
    print(json.dumps({"migration_id":MIGRATION_ID,"schema_version_after":SCHEMA_VERSION_AFTER,"apply_supported":False,"writer_mode":"v1","dynamic_legacy_policy":"VERSION_UNKNOWN_LEGACY","statements":list(DDL)},indent=2))
    return 0
if __name__ == '__main__': raise SystemExit(main())
