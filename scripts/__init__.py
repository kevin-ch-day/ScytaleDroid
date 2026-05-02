"""Repository automation scripts package (minimal; enables scripts.db imports)."""

from __future__ import annotations


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="scripts",
        description="Package marker for ./scripts/. Run leaf scripts under scripts/db/ or scripts/*.py.",
    )
    parser.parse_args()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
