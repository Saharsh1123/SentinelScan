# Development Guide

This document covers local setup, testing, linting, project structure, and development workflow for SentinelScan.

SentinelScan uses only Python standard-library modules at runtime. Development tooling uses `pytest` and `ruff`.

---

## Local Setup

```bash
git clone https://github.com/Saharsh1123/SentinelScan.git
cd SentinelScan
python3 -m venv venv
source venv/bin/activate
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

```bash
python3 main.py ./your_directory
python3 main.py test_dirs
python3 main.py test_dirs --json
python3 main.py test_dirs --severity HIGH
python3 main.py test_dirs --confidence HIGH
python3 main.py test_dirs --redact
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

Run a folder:

```bash
pytest tests/test_ast
pytest tests/test_cli
```

Run one test:

```bash
pytest tests/test_ast/test_ast_dict_literals.py::test_ast_dict_literal_password_key
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

Recommended prefixes:

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
git commit -m "feat: detect secrets in dictionary literals"
git commit -m "refactor: split per-file scanning logic"
git commit -m "docs: update detection rule documentation"
```

---

## Development Workflow

Use small, focused changes.

```text
1. Pick one behavior
2. Add or update focused tests
3. Run the targeted test
4. Implement the change
5. Run the targeted test again
6. Run the full test suite
7. Run Ruff
8. Manually test CLI behavior if needed
9. Update relevant docs
10. Commit implementation + tests together when practical
```

Avoid mixing unrelated features, refactors, and documentation changes in one commit.

---

## Current Feature Areas

SentinelScan currently includes:

- AST-based Python scanning
- simple assignment detection
- annotated assignment detection
- attribute assignment detection
- subscript assignment detection
- dictionary literal detection
- modular rule engine
- structured dataclass models
- entropy metadata
- confidence scoring
- text and JSON output
- severity filtering
- confidence filtering
- redaction
- `.sentinelscanignore`
- generic inline ignores
- rule-specific inline ignores
- Ruff linting
- pytest coverage
- GitHub Actions CI

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
├── test_dirs/
├── tests/
│   ├── test_ast/
│   ├── test_cli/
│   ├── helpers.py
│   ├── test_apply_rules.py
│   ├── test_confidence.py
│   ├── test_ignore.py
│   ├── test_inline_ignore.py
│   └── test_scanner.py
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

## Architecture Guidelines

- Detection should use original values.
- Redaction should happen only in the output layer.
- File path handling should stay in the scanner layer.
- AST extraction should not depend on filesystem paths.
- Candidate extraction should produce `Candidate` objects, not findings.
- Rule evaluation should produce `Finding` objects, not output text.
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
