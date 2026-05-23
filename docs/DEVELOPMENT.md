# Development Guide

This document covers local setup, testing, linting, project structure, and development workflow for SentinelScan.

SentinelScan uses only Python standard-library modules at runtime. Development tooling uses `pytest` and `ruff`.

---

## Local Setup

Clone the repository:

```bash
git clone https://github.com/Saharsh1123/SentinelScan.git
cd SentinelScan
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

Install development dependencies:

```bash
python3 -m pip install pytest ruff
```

Verify tools:

```bash
python3 --version
pytest --version
ruff --version
```

---

## Running SentinelScan

Scan a directory:

```bash
python3 main.py ./your_directory
```

Scan fixtures:

```bash
python3 main.py test_dirs
```

JSON output:

```bash
python3 main.py test_dirs --json
```

Severity filter:

```bash
python3 main.py test_dirs --severity HIGH
```

Confidence filter:

```bash
python3 main.py test_dirs --confidence HIGH
```

Redaction:

```bash
python3 main.py test_dirs --redact
```

Combined options:

```bash
python3 main.py test_dirs --json --severity HIGH --confidence HIGH --redact
```

---

## Linting and Formatting

Run Ruff:

```bash
ruff check .
```

Auto-fix safe issues:

```bash
ruff check . --fix
```

Format code:

```bash
ruff format .
```

---

## Testing

Run all tests:

```bash
pytest
```

Run a specific file:

```bash
pytest tests/test_confidence.py
```

Run a folder:

```bash
pytest tests/test_ast
pytest tests/test_cli
```

Run one test:

```bash
pytest tests/test_ast/test_ast_subscripts.py::test_ast_subscript_password_assignment
```

Quiet mode:

```bash
pytest -q
```

---

## Pre-Commit Check

Run before committing:

```bash
ruff check .
pytest
```

For CLI behavior changes, also run:

```bash
python3 main.py test_dirs
python3 main.py test_dirs --json
python3 main.py test_dirs --json --severity HIGH
python3 main.py test_dirs --json --confidence HIGH
python3 main.py test_dirs --json --severity HIGH --confidence HIGH --redact
```

---

## Commit Workflow

```bash
git status
git add .
git commit -m "your commit message"
git push
```

Recommended commit prefixes:

```text
feat: user-facing feature
fix: bug fix
refactor: internal structure change
test: test updates
docs: documentation update
ci: workflow/automation update
chore: maintenance
```

Examples:

```bash
git commit -m "feat: add confidence filtering"
git commit -m "feat: add sentinelscanignore support"
git commit -m "refactor: split CLI tests by responsibility"
git commit -m "test: add subscript assignment coverage"
git commit -m "docs: update architecture documentation"
```

---

## Development Workflow

Use small, focused changes.

```text
1. Pick one behavior
2. Add or update a focused test
3. Run the targeted test
4. Implement the change
5. Run the targeted test again
6. Run the full test suite
7. Run Ruff
8. Manually test CLI behavior if needed
9. Update relevant docs
10. Commit
```

Avoid mixing unrelated feature, refactor, test, and documentation changes in one commit.

---

## Current Feature Areas

SentinelScan currently includes:

- AST-based Python scanning
- Simple assignment detection
- Attribute assignment detection
- Subscript assignment detection
- Modular rule engine
- Structured dataclass models
- Entropy metadata
- Confidence scoring
- Text and JSON output
- Severity filtering
- Confidence filtering
- Redaction
- `.sentinelscanignore`
- Generic inline ignores
- Rule-specific inline ignores
- Ruff linting
- Pytest coverage
- GitHub Actions test workflow

---

## Project Structure

```text
SENTINELSCAN/
├── .github/workflows/tests.yaml
├── detectors/
│   ├── ast_analyzer.py
│   ├── confidence.py
│   ├── find_secrets.py
│   ├── models.py
│   ├── rule_engine.py
│   └── rules.py
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DETECTION_RULES.md
│   ├── DEVELOPMENT.md
│   ├── ROADMAP.md
│   ├── TESTING.md
│   └── USAGE.md
├── test_dirs/
├── tests/
│   ├── test_ast/
│   ├── test_cli/
│   ├── helpers.py
│   ├── test_apply_rules.py
│   ├── test_confidence.py
│   ├── test_ignore.py
│   └── test_inline_ignore.py
├── .sentinelscanignore
├── cli.py
├── ignore.py
├── inline_ignore.py
├── main.py
├── output.py
├── scanner.py
└── pytest.ini
```

Generated files such as `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, `.vscode/`, and `venv/` should not be committed unless intentionally configured.

---

## Module Overview

| Module | Responsibility |
|---|---|
| `cli.py` | Parse command-line arguments |
| `main.py` | Coordinate scan flow |
| `scanner.py` | Validate paths, discover/read files, apply source suppression |
| `ignore.py` | Load and apply `.sentinelscanignore` patterns |
| `inline_ignore.py` | Handle generic and rule-specific inline ignores |
| `output.py` | Filter, redact, format, and serialize findings |
| `detectors/ast_analyzer.py` | Parse AST and extract candidates |
| `detectors/rule_engine.py` | Apply rules and create findings |
| `detectors/confidence.py` | Calculate entropy and confidence |
| `detectors/models.py` | Define dataclasses |
| `detectors/rules.py` | Define built-in rules |
| `detectors/find_secrets.py` | Coordinate candidate extraction and rule evaluation |

---

## Testing Map

| Feature Type | Test Location |
|---|---|
| Rule engine behavior | `tests/test_apply_rules.py` |
| Confidence behavior | `tests/test_confidence.py` |
| AST extraction | `tests/test_ast/` |
| CLI behavior | `tests/test_cli/` |
| Ignore file behavior | `tests/test_ignore.py` |
| Inline ignore behavior | `tests/test_inline_ignore.py` |

Add tests with every feature change.

---

## Architecture Guidelines

- Detection should use original values.
- Redaction should happen only in the output layer.
- File path handling should stay in the scanner layer.
- AST extraction should not depend on filesystem paths.
- `.sentinelscanignore` should remain a plain text pattern file.
- Inline ignores should suppress findings after detection.
- JSON output should remain machine-readable and free of human-readable scan text.
- Future config precedence should be: defaults → config file → CLI flags.

---

## Documentation Updates

Update documentation when behavior changes.

| Change Type | Likely Docs |
|---|---|
| CLI option | `README`, `docs/USAGE.md`, `docs/DEVELOPMENT.md` |
| Detection behavior | `docs/DETECTION_RULES.md`, `docs/ARCHITECTURE.md` |
| Internal structure | `docs/ARCHITECTURE.md`, `docs/DEVELOPMENT.md` |
| Testing strategy | `docs/TESTING.md`, `docs/DEVELOPMENT.md` |
| Roadmap change | `docs/ROADMAP.md` |