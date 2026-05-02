"""Operational database tooling."""

from __future__ import annotations


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="scripts.db",
        description="Operational DB tooling package. Run scripts under scripts/db/*.py.",
    )
    parser.parse_args()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
