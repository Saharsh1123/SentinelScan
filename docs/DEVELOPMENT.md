# Development Guide

This document covers local setup, linting, formatting, project structure, and recommended development workflow.

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

SentinelScan currently uses only Python standard-library modules at runtime.

---

## Running the Tool Locally

Scan a directory:

```bash
python3 main.py ./your_directory
```

Scan fixtures:

```bash
python3 main.py test_dirs
```

Run JSON output:

```bash
python3 main.py test_dirs --json
```

Run severity filtering:

```bash
python3 main.py test_dirs --severity HIGH
```

Run redacted JSON output:

```bash
python3 main.py test_dirs --json --redact
```

Run combined flags:

```bash
python3 main.py test_dirs --json --severity HIGH --redact
```

---

## Linting and Formatting

Run Ruff:

```bash
ruff check .
```

Auto-fix safe lint issues:

```bash
ruff check . --fix
```

Format code:

```bash
ruff format .
```

Ruff is used to keep the codebase clean and catch common issues such as:

- Unused imports
- Formatting problems
- Simple style issues
- Common Python mistakes

---

## Recommended Check Before Committing

```bash
ruff check .
pytest
python3 main.py test_dirs
python3 main.py test_dirs --json
python3 main.py test_dirs --json --severity HIGH
python3 main.py test_dirs --json --severity HIGH --redact
```

---

## Suggested Commit Flow

```bash
git status
git add .
git commit -m "your commit message"
git push
```

Recommended commit message types:

```text
feat: add new user-facing behavior
fix: correct broken behavior
refactor: improve internal structure without changing behavior
test: add or update tests
docs: update documentation
ci: update GitHub Actions or automation
chore: maintenance work
```

Examples:

```bash
git commit -m "feat: add redacted output mode"
git commit -m "refactor: add structured rule engine models"
git commit -m "test: add CLI redaction coverage"
git commit -m "docs: split project documentation"
```

---

## Project Structure

```text
SENTINELSCAN/
├── .github/
│   └── workflows/
│       └── tests.yaml              # GitHub Actions workflow for Ruff and pytest
├── detectors/
│   ├── __init__.py                 # Makes detectors an importable package
│   ├── ast_analyzer.py             # AST parsing and candidate extraction
│   ├── find_secrets.py             # High-level detection orchestration
│   ├── models.py                   # Rule, Candidate, and Finding dataclasses
│   ├── rule_engine.py              # Applies rules to candidates
│   └── rules.py                    # Built-in rule definitions
├── test_dirs/
│   ├── edge_repo/
│   │   └── edge_test.py            # Edge-case fixture file
│   └── test_repo/
│       ├── embedded_test/
│       │   └── embedded_hello.py   # Nested fixture file
│       ├── hello.py                # Benign fixture file
│       └── open_vulns.py           # Fixture file containing sample vulnerabilities
├── tests/
│   ├── test_apply_rules.py         # Unit tests for rule engine behavior
│   ├── test_ast.py                 # Tests for AST-based detection
│   └── test_cli.py                 # CLI integration tests
├── .gitignore
├── cli.py                          # CLI argument parsing
├── LICENSE
├── main.py                         # Application entry point
├── output.py                       # JSON/text output formatting, filtering, and redaction
├── pytest.ini                      # Pytest import path configuration
├── README.md                       # Project overview
└── scanner.py                      # Path validation, file discovery, file reading, and scan orchestration
```

Generated local files such as `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, and `venv/` may appear during development but should not be committed.

---

## Development Notes

### Keep Detection and Output Separate

The rule engine should detect findings using original values.

Output formatting should decide whether to display original values or redacted values.

### Keep File Paths in the Scanner Layer

The scanner knows which file is being read, so it attaches file paths to findings.

The AST analyzer and rule engine should not depend on file-system paths.

### Prefer Structured Models Over Tuples

Use dataclass fields such as:

```text
finding.rule_id
finding.rule_name
finding.severity
finding.value
finding.reason
```

Avoid returning large tuples where field order must be memorized.

### Add Tests With Every Feature

New CLI behavior should have CLI tests.

New rule behavior should have rule-engine and AST tests where appropriate.
