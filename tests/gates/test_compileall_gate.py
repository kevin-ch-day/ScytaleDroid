from __future__ import annotations

from pathlib import Path


def test_repo_python_files_compile() -> None:
    """Catch syntax/indentation errors in rarely-imported modules.

    This is intentionally a broad gate: we want PRs to fail fast if they introduce
    parse-time errors anywhere under scytaledroid/ or scripts/.

    Sources are compiled in memory: compileall would write __pycache__ files into
    the checkout, which fails on a read-only (sandboxed) tree and leaves debris.
    """

    root = Path(__file__).resolve().parents[2]
    errors: list[str] = []
    for package in ("scytaledroid", "scripts"):
        for path in sorted((root / package).rglob("*.py")):
            try:
                compile(path.read_bytes(), str(path), "exec", dont_inherit=True)
            except (SyntaxError, ValueError) as exc:
                errors.append(f"{path.relative_to(root)}: {exc}")
    assert not errors, "\n".join(errors)
