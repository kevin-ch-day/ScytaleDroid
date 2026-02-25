# Versioning and Deprecation Policy

## Versioning

ScytaleDroid follows semantic versioning (SemVer):

- **Major** (`X.0.0`): breaking changes to supported interfaces or contracts.
- **Minor** (`0.Y.0`): new features, backwards compatible.
- **Patch** (`0.0.Z`): bug fixes, backwards compatible.

## Supported Interfaces

The supported public interface is defined in:

- `docs/supported_entrypoints.md`

Anything not listed there is best-effort and may change without notice.

## Deprecation

When an interface is deprecated:

- A compatibility shim/wrapper may be kept for **one major cycle**.
- The shim must emit a one-line stderr warning when executed directly, including
  the planned removal version (e.g., "removal planned in v3.0").
- Deprecated shims are removed in the next major release.

Example: If the current release line is v2.x, deprecated wrappers are removed in v3.0.

