# Development

This document covers local setup and the basic development workflow.

---

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
python3 -m pip install pytest ruff
```

---

## Local Checks

```bash
ruff check .
ruff format .
pytest
```

Smoke tests:

```bash
python3 main.py test_dirs
python3 main.py test_dirs --json
python3 main.py test_dirs --severity HIGH MEDIUM --confidence HIGH --redact
```

---

## Workflow

1. Design the feature or refactor.
2. Add focused tests with the change.
3. Keep commits scoped to one logical purpose.
4. Update docs when behavior changes.
5. Run Ruff and pytest before pushing.

---

## Project Rules

- Keep detectors separate from output formatting.
- Keep AST extraction separate from rule evaluation.
- Keep config loading separate from CLI parsing.
- Prefer small helpers over large branching functions.
- Do not commit generated files, caches, virtualenvs, or ZIP archives.
