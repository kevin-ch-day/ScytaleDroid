# Permission Intel vs Erebus database (discussion stub)

**Agreed baseline**

- **ScytaleDroid Permission Intel** targets the MariaDB catalog **`android_permission_intel`** (configured via `SCYTALEDROID_PERMISSION_INTEL_DB_NAME` or URL path).
- **Erebus** is a different product/tooling path: it uses **`EREBUS_*`** (or project-specific) env vars and its **own** database catalog — not interchangeable with ScytaleDroid’s Permission Intel DSN in documentation or mental model.

**Open points (for operator / architecture chat)**

- Whether any host ever runs **both** schemas on one MariaDB **instance** (still two catalogs) vs fully separate servers.
- Whether governance CSV / snapshot imports should always land in `android_permission_intel` for ScytaleDroid paper-grade checks, and how Erebus-published snapshots relate (provenance / `source_system` in governance tables).

Update this note when deployment conventions are finalized.
