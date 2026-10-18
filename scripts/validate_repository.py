"""Command-line entry point for repository validation."""

from __future__ import annotations

from monitoring import main


if __name__ == "__main__":
    raise SystemExit(main(["validate", "."]))
