"""Module entrypoint wrapper for headless static analysis runs."""

from __future__ import annotations

from .flows.headless_run import main


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
