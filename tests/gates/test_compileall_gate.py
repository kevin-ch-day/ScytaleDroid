from __future__ import annotations

import compileall
from pathlib import Path


def test_repo_python_files_compile() -> None:
    """Catch syntax/indentation errors in rarely-imported modules.

    This is intentionally a broad gate: we want PRs to fail fast if they introduce
    parse-time errors anywhere under scytaledroid/ or scripts/.
    """

    root = Path(__file__).resolve().parents[2]
    # compileall returns False if any file fails to compile.
    assert compileall.compile_dir(str(root / "scytaledroid"), quiet=1)
    assert compileall.compile_dir(str(root / "scripts"), quiet=1)

