# ScytaleDroid

ScytaleDroid v2 is a menu-driven toolkit for harvesting, cataloging, and analyzing
Android application packages (APKs) from real devices. The project emphasizes a
"database-first" design so every artifact is traced by an `apk_id`, paired with
predictable filenames, and ready for follow-on static, dynamic, or threat-intel
analysis.

- **Quick start:** `./run.sh` launches the CLI. Use *Device Analysis → 5* to
  capture an inventory, then *Device Analysis → 7* to harvest scoped APKs.
- **Why v2:** replaces the JSON/CSV-heavy v1 tooling with durable tables, strict
  filename conventions, and scoped harvesting so investigators pull only the
  data they need.
- **Current focus:** finishing the Device Analysis loop (inventory → scoped
  harvest → repository records). Static/dynamic/threat-intel phases will build
  on the shared `apk_id` identifiers.

For a detailed overview tailored to collaborators, including what is finished,
what we are tightening now, and how others can help, see
[`docs/device_analysis/README.md`](docs/device_analysis/README.md).
