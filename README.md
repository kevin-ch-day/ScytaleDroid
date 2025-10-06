# ScytaleDroid

ScytaleDroid v2 is a menu-driven toolkit for harvesting, cataloging, and analyzing
Android application packages (APKs) from real devices. The project emphasizes a
"database-first" design so every artifact is traced by an `apk_id`, paired with
predictable filenames, and ready for follow-on static, dynamic, or threat-intel
analysis.

- **Quick start:** `./run.sh` launches the CLI. Use *Device Analysis → 5* to
  capture an inventory, then *Device Analysis → 7* to harvest scoped APKs. When
  inventories are only soft-stale the pull step defaults to the quick-harvest
  path, which resolves APK locations live with `pm path` so you can grab fresh
  artifacts without taking a full filesystem snapshot.
- **Why v2:** replaces the JSON/CSV-heavy v1 tooling with durable tables, strict
  filename conventions, and scoped harvesting so investigators pull only the
  data they need.
- **Current focus:** tightening the Device Analysis loop (inventory → scoped
  harvest → repository records). Static/dynamic/threat-intel phases build on the
  shared `apk_id` identifiers and the new quick-harvest helpers that dedupe by
  `sha256`, emit metadata sidecars, and optionally persist database records on
  the fly.

### Harvest configuration highlights

- `HARVEST_DEDUP_SHA256` / `HARVEST_KEEP_LAST` control hash-based dedupe. Keep
  quick re-pulls light by skipping identical artifacts or force the latest copy
  when needed.
- `HARVEST_WRITE_DB` toggles repository writes so test runs can avoid touching
  the database while still producing on-disk artifacts and metadata.
- `HARVEST_META_FIELDS` accepts a comma-delimited list of metadata keys so the
  sidecar `*.meta.json` files stay focused on the attributes your workflow
  expects.

For a detailed overview tailored to collaborators, including what is finished,
what we are tightening now, and how others can help, see
[`docs/device_analysis/README.md`](docs/device_analysis/README.md).
