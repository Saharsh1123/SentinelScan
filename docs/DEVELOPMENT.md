# Development

This document covers local setup and the development workflow.

---

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

Install Git hooks once per clone:

```bash
python3 -m pre_commit install
```

---

## Local Checks

```bash
python3 -m black --check .
python3 -m ruff check .
python3 -m pytest
```

To apply formatting locally:

```bash
python3 -m black .
python3 -m ruff check . --fix
```

Smoke tests:

```bash
python3 main.py test_dirs
python3 main.py test_dirs --format json
python3 main.py test_dirs --format sarif
python3 main.py test_dirs --severity HIGH MEDIUM --confidence HIGH
python3 main.py test_dirs --unsafe-show-secrets
```

Focused SARIF checks:

```bash
python3 -m pytest tests/test_output/test_sarif_output.py tests/test_cli/test_cli_sarif.py
python3 main.py test_dirs --format sarif > sentinelscan.sarif
```

---

## Workflow

1. Design the feature or refactor.
2. Add focused tests with the change.
3. Keep commits scoped to one logical purpose.
4. Update docs, docstrings, and comments when behavior changes.
5. Run Black, Ruff, and pytest before pushing.
6. Confirm the GitHub Actions matrix passes on Ubuntu and Windows.

---

## Project Rules

- Keep detectors separate from output formatting.
- Keep AST extraction separate from rule evaluation.
- Keep SARIF serialization separate from generic output dispatch.
- Keep config loading separate from CLI parsing.
- Prefer small helpers over large branching functions.
- Test public behavior instead of internal implementation details.
- Do not commit generated reports, caches, virtual environments, or ZIP archives.
