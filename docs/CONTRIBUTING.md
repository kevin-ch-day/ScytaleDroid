# Contributing to ScytaleDroid

Thanks for your interest in helping ScytaleDroid grow! This document describes how we work,
the standards we follow, and the checks we expect contributors to run before opening a
pull request.

## Code of Conduct

Participation in the project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). We
expect everyone to help create a welcoming, inclusive, and respectful environment.

## Getting started

1. Fork the repository and clone your fork locally.
2. Create a topic branch off `main` that describes the change you plan to make.
3. Install dependencies:
   ```bash
   ./setup.sh
   python -m pip install --upgrade ruff pytest
   ```
4. Ensure you can talk to any required services (Android devices, databases) before running
the CLI.

## Development workflow

- **Keep changes focused.** Smaller, self-contained pull requests are easier to review.
- **Document behaviour.** Update the README, docs, or inline comments when you add or modify
  user-facing functionality.
- **Write tests.** When possible, cover new logic with unit or integration tests under
  `tests/`.
- **Follow the style guide.** The project targets Python 3.13 with Ruff enforcing PEP 8
  conventions and quality rules. Type hints are encouraged; mypy configuration lives in
  `pyproject.toml`.
- **Commit messages.** Use present tense and explain *why* the change is needed. Example:
  `Add adb connectivity checks to device harvester`.
- **Pull request description.** Summarise the change, highlight testing performed, and call
  out any follow-up work that remains.

## Before submitting a pull request

Run the automated checks locally so the CI pipeline can pass cleanly:

```bash
ruff check .
ruff format --check .
pytest
```

If you add new CLI behaviours, also exercise the relevant menu flows to confirm the UX is
sound. When tests require device or database access, document any limitations in the pull
request.

## Reporting issues

- Use GitHub issues to report bugs, request features, or ask for clarifications.
- Include reproduction steps, expected vs. actual behaviour, and any relevant CLI output.
- Security-sensitive reports should be sent privately—do not open public issues with
  exploit details.

We appreciate your contributions and look forward to collaborating with you!
