# Security Policy

## Scope

ScytaleDroid handles research data, device-derived artifacts, static-analysis findings, and database-backed evidence.
Because this repo can process sensitive material, treat the following as security boundaries:

- Do not commit harvested APK payloads, evidence packs, packet captures, or device exports.
- Do not commit database backups, SQL dumps, or schema snapshots taken from live environments.
- Do not commit live credentials, API keys, bearer tokens, private keys, or production `.env` files.
- Treat static-analysis findings that quote third-party secret-like strings as sensitive evidence, not safe fixture text.

## Supported Security Posture

Security fixes are applied to the active `main` branch in this repository.
Older local branches, ad-hoc checkpoints, and deleted historical dumps are not treated as supported release lines.

## Reporting a Vulnerability

If you find a vulnerability or exposed credential:

1. Do not open a public issue with the raw secret or exploit details.
2. Use GitHub Security Advisories / private vulnerability reporting for this repository when available.
3. If private reporting is unavailable, contact the maintainer directly and include:
   - affected path or component
   - impact summary
   - reproduction steps
   - whether credential rotation or history cleanup is likely required

## Repository Hygiene Rules

- Keep `.env` local; use `.env.example` for non-sensitive configuration contracts.
- Keep backup and dump artifacts outside the Git worktree or in ignored local paths.
- Use redacted or runtime-built placeholders in tests when matching secret-shaped patterns.
- Prefer evidence summaries and hashed/redacted derivatives over raw secret-bearing payloads in reports and fixtures.

## Response Expectations

Security triage in this repo usually follows:

1. confirm whether the material is current-source, generated output, or historical Git content
2. remove or redact the current-source exposure
3. rotate real credentials if applicable
4. decide whether Git history rewrite is required for old committed dumps or secrets

Historical research backups and deleted dump files may still require alert resolution even after they are removed from the working tree.
