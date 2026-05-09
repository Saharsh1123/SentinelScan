# Testing

This document explains SentinelScan's test strategy, pytest usage, CLI test coverage, and continuous integration behavior.

---

## Running Tests

Run all tests:

```bash
pytest
```

Or:

```bash
python3 -m pytest
```

---

## Test Suite Coverage

The test suite covers:

- Rule engine behavior
- Rule dataclass behavior through rule evaluation
- Candidate-to-finding flow
- AST-based candidate extraction
- AST-based secret detection
- Variable-name-based detection
- Value-pattern-based detection
- AWS access key detection
- Password/API key/token/secret detection
- Multiple assignment targets
- Multiple classifications from one candidate
- Nested attribute extraction
- Syntax error handling
- Non-string assignment handling
- Unsupported subscript target handling
- JSON output validity
- JSON schema fields
- JSON field types
- Text output sections
- Severity filtering
- Combined `--json --severity`
- Redaction in text output
- Redaction in JSON output
- Combined `--json --severity --redact`
- No-finding behavior
- Invalid path behavior
- Invalid severity behavior

---

## Test Files

```text
tests/
├── test_apply_rules.py     # Unit tests for rule engine behavior
├── test_ast.py             # Tests for AST-based detection
└── test_cli.py             # CLI integration tests
```

### `test_apply_rules.py`

Tests the rule engine directly.

Focus areas:

- Candidate-to-finding conversion
- Variable-name-based rules
- Value-pattern-based rules
- AWS access key detection
- Minimum-length behavior
- Rule metadata preservation
- Line-number preservation
- No-match behavior

### `test_ast.py`

Tests AST-based detection.

Focus areas:

- Simple assignments
- Attribute assignments
- Nested attributes
- Multiple targets
- Multiple classifications
- Syntax errors
- Unsupported AST targets
- Non-string assignment filtering

### `test_cli.py`

Tests the actual CLI through `subprocess`.

Focus areas:

- JSON output
- Text output
- Severity filtering
- Redaction
- Combined flags
- Invalid input handling
- No-finding behavior
- Schema consistency

---

## Why CLI Tests Use `subprocess`

CLI tests run real commands such as:

```bash
python3 main.py test_dirs --json
```

The tests use Python's current interpreter through `sys.executable` to stay consistent across local development and CI.

This validates the actual user-facing behavior instead of only testing internal functions.

---

## Continuous Integration

SentinelScan uses GitHub Actions to run automated checks on pushes and pull requests.

Workflow file:

```text
.github/workflows/tests.yaml
```

The workflow is intended to:

- Check out the repository
- Set up Python
- Install development dependencies
- Run Ruff
- Run pytest

This catches regressions in a clean environment.

---

## Recommended Local Check

Before committing:

```bash
ruff check .
pytest
python3 main.py test_dirs
python3 main.py test_dirs --json
python3 main.py test_dirs --json --severity HIGH
python3 main.py test_dirs --json --severity HIGH --redact
```

---

## Pytest Configuration

`pytest.ini` is used to configure import behavior so tests can import project modules cleanly.

Typical purpose:

```text
Make the repository root available on the Python import path during tests.
```
