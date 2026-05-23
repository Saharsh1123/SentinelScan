# Testing

This document explains SentinelScan's test strategy, pytest usage, CLI coverage, and continuous integration behavior.

---

## Running Tests

Run the full test suite:

```bash
pytest
```

Equivalent command:

```bash
python3 -m pytest
```

Run tests quietly:

```bash
pytest -q
```

Run a specific test file:

```bash
pytest tests/test_confidence.py
```

Run a specific test folder:

```bash
pytest tests/test_ast
pytest tests/test_cli
```

Run one test:

```bash
pytest tests/test_ast/test_ast_subscripts.py::test_ast_subscript_password_assignment
```

---

## Test Strategy

SentinelScan uses a mix of unit tests and CLI integration tests.

| Test Type | Purpose |
|---|---|
| Unit tests | Validate individual modules and helper functions |
| AST tests | Validate candidate extraction and detection behavior |
| Rule engine tests | Validate rule matching and finding creation |
| CLI tests | Validate real user-facing command behavior |
| Ignore tests | Validate file-level and inline suppression |
| Confidence tests | Validate entropy and confidence scoring |

The goal is to test both internal behavior and actual CLI behavior.

---

## Test Suite Coverage

The test suite covers:

- Rule engine behavior
- Candidate-to-finding flow
- AST-based extraction
- Simple assignment detection
- Attribute assignment detection
- Subscript assignment detection
- Variable-name-based detection
- Value-pattern-based detection
- AWS access key detection
- Password/API key/token/secret detection
- Multiple assignment targets
- Multiple classifications from one candidate
- Syntax error handling
- Non-string assignment handling
- Unsupported AST target handling
- Entropy calculation
- Confidence scoring
- JSON output validity
- JSON schema fields
- JSON field types
- Text output behavior
- Severity filtering
- Confidence filtering
- Redaction in text output
- Redaction in JSON output
- `.sentinelscanignore` behavior
- Generic inline ignores
- Rule-specific inline ignores
- No-finding behavior
- Invalid path behavior
- Invalid CLI choice behavior

---

## Test Layout

```text
tests/
├── test_ast/
│   ├── __init__.py
│   ├── ast_helpers.py
│   ├── test_ast_attributes.py
│   ├── test_ast_core.py
│   └── test_ast_subscripts.py
├── test_cli/
│   ├── test_cli_errors.py
│   ├── test_cli_filters.py
│   ├── test_cli_ignore.py
│   ├── test_cli_inline_ignore.py
│   ├── test_cli_output.py
│   └── test_cli_redaction.py
├── __init__.py
├── helpers.py
├── test_apply_rules.py
├── test_confidence.py
├── test_ignore.py
└── test_inline_ignore.py
```

---

## Test File Responsibilities

| File | Purpose |
|---|---|
| `tests/test_apply_rules.py` | Rule engine behavior |
| `tests/test_confidence.py` | Entropy and confidence scoring |
| `tests/test_ignore.py` | `.sentinelscanignore` unit behavior |
| `tests/test_inline_ignore.py` | Inline ignore unit and scanner behavior |
| `tests/helpers.py` | Shared CLI test helpers |
| `tests/test_ast/ast_helpers.py` | Shared AST assertion helpers |
| `tests/test_ast/test_ast_core.py` | Core AST detection behavior |
| `tests/test_ast/test_ast_attributes.py` | Attribute assignment extraction |
| `tests/test_ast/test_ast_subscripts.py` | Subscript assignment extraction |
| `tests/test_cli/test_cli_output.py` | JSON and text output behavior |
| `tests/test_cli/test_cli_filters.py` | Severity and confidence filters |
| `tests/test_cli/test_cli_ignore.py` | `.sentinelscanignore` CLI behavior |
| `tests/test_cli/test_cli_inline_ignore.py` | Inline ignore CLI behavior |
| `tests/test_cli/test_cli_redaction.py` | Redaction behavior |
| `tests/test_cli/test_cli_errors.py` | Invalid CLI input behavior |

---

## AST Tests

AST tests validate detection without invoking the CLI.

Covered areas:

- Simple assignments
- Attribute assignments
- Nested attributes
- Subscript assignments
- Nested subscript assignments
- Multiple assignment targets
- Multiple classifications
- Syntax errors
- Non-string assignments
- Unsupported subscript keys
- Line-number preservation
- Entropy and confidence metadata

Example command:

```bash
pytest tests/test_ast
```

---

## Rule Engine Tests

Rule engine tests validate direct candidate-to-finding behavior.

Covered areas:

- Variable-name rules
- Value-pattern rules
- AWS access key matching
- Minimum-length behavior
- Rule metadata preservation
- Confidence metadata
- No-match behavior
- Multiple findings from one candidate

Example command:

```bash
pytest tests/test_apply_rules.py
```

---

## Confidence Tests

Confidence tests validate entropy and confidence behavior.

Covered areas:

- Shannon entropy calculation
- Empty values
- Repetitive values
- Common/test values
- Low/medium/high confidence thresholds
- AWS access key confidence behavior

Example command:

```bash
pytest tests/test_confidence.py
```

---

## Ignore Tests

Ignore tests validate suppression behavior.

Covered areas:

- Missing ignore files
- Blank lines and comments
- Ignored files
- Ignored directories
- Glob patterns
- Parent `.sentinelscanignore` discovery
- Generic inline ignores
- Rule-specific inline ignores
- String literals containing ignore markers

Example commands:

```bash
pytest tests/test_ignore.py
pytest tests/test_inline_ignore.py
```

---

## CLI Tests

CLI tests run SentinelScan through `subprocess`.

They validate real user-facing behavior, including:

- JSON output
- Text output
- Severity filtering
- Confidence filtering
- Redaction
- File ignore behavior
- Inline ignore behavior
- Invalid CLI choices
- Invalid paths
- No-finding behavior

Example command:

```bash
pytest tests/test_cli
```

---

## Why CLI Tests Use `subprocess`

CLI tests run real commands using the current Python interpreter:

```bash
python3 main.py test_dirs --json
```

Internally, tests use `sys.executable` so local development and CI use the same interpreter that is running pytest.

This validates actual command-line behavior instead of only testing internal functions.

---

## Continuous Integration

SentinelScan uses GitHub Actions for automated checks.

Workflow file:

```text
.github/workflows/tests.yaml
```

The workflow is expected to:

- Check out the repository
- Set up Python
- Install development dependencies
- Run Ruff
- Run pytest

This catches regressions in a clean environment.

---

## Recommended Local Check

Before committing, run:

```bash
ruff check .
pytest
```

For CLI-facing changes, also run:

```bash
python3 main.py test_dirs
python3 main.py test_dirs --json
python3 main.py test_dirs --json --severity HIGH
python3 main.py test_dirs --json --confidence HIGH
python3 main.py test_dirs --json --severity HIGH --confidence HIGH --redact
```

For ignore-related changes, also test:

```bash
python3 main.py .
python3 main.py test_dirs
```

---

## Pytest Configuration

`pytest.ini` configures pytest behavior for the project.

Its main purpose is to keep imports stable so tests can import project modules cleanly from the repository root.

---

## Testing Guidelines

- Add tests with every behavior change.
- Prefer focused tests over broad tests.
- Keep unit tests close to the module behavior being validated.
- Use CLI tests for user-facing behavior.
- Keep JSON output tests strict enough to catch broken schemas.
- Keep helper assertions centralized to avoid duplicate test logic.
- Avoid relying on local machine state or untracked files.