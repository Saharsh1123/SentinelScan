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

SentinelScan uses unit tests and CLI integration tests.

| Test Type | Purpose |
|---|---|
| Unit tests | Validate individual modules and helper functions |
| AST tests | Validate candidate extraction and detection behavior |
| Rule engine tests | Validate candidate-to-finding behavior |
| CLI tests | Validate real user-facing command behavior |
| Ignore tests | Validate file-level and inline suppression |
| Confidence tests | Validate entropy and confidence scoring |

The goal is to test both internal behavior and actual CLI behavior.

---

## Test Suite Coverage

The test suite covers:

- rule engine behavior
- candidate-to-finding flow
- AST-based extraction
- simple assignment detection
- annotated assignment detection
- attribute assignment detection
- subscript assignment detection
- dictionary literal detection
- variable-name-based detection
- value-pattern-based detection
- AWS access key detection
- password/API key/token/secret detection
- multiple assignment targets
- multiple classifications from one candidate
- syntax error handling
- non-string assignment handling
- unsupported AST target handling
- entropy calculation
- confidence scoring
- JSON output validity
- JSON schema fields
- JSON field types
- text output behavior
- severity filtering
- confidence filtering
- redaction in text output
- redaction in JSON output
- `.sentinelscanignore` behavior
- generic inline ignores
- rule-specific inline ignores
- no-finding behavior
- invalid path behavior
- invalid CLI choice behavior

---

## Test Layout

```text
tests/
├── test_ast/
│   ├── __init__.py
│   ├── ast_helpers.py
│   ├── test_ast_annotations.py
│   ├── test_ast_attributes.py
│   ├── test_ast_core.py
│   ├── test_ast_dict_literals.py
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
├── test_inline_ignore.py
└── test_scanner.py
```

---

## Test File Responsibilities

| File | Purpose |
|---|---|
| `tests/test_apply_rules.py` | Rule engine behavior |
| `tests/test_confidence.py` | Entropy and confidence scoring |
| `tests/test_ignore.py` | `.sentinelscanignore` unit behavior |
| `tests/test_inline_ignore.py` | Inline ignore behavior |
| `tests/test_scanner.py` | Scanner and per-file scan behavior |
| `tests/helpers.py` | Shared CLI test helpers |
| `tests/test_ast/ast_helpers.py` | Shared AST assertion helpers |
| `tests/test_ast/test_ast_core.py` | Core AST detection behavior |
| `tests/test_ast/test_ast_annotations.py` | Annotated assignment extraction |
| `tests/test_ast/test_ast_attributes.py` | Attribute assignment extraction |
| `tests/test_ast/test_ast_subscripts.py` | Subscript assignment extraction |
| `tests/test_ast/test_ast_dict_literals.py` | Dictionary literal extraction |
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

- simple assignments
- annotated assignments
- attribute assignments
- nested attributes
- subscript assignments
- nested subscript assignments
- dictionary literals
- multiple assignment targets
- multiple classifications
- syntax errors
- non-string assignments
- unsupported subscript keys
- unsupported dictionary entries
- line-number preservation
- entropy and confidence metadata

Example command:

```bash
pytest tests/test_ast
```

---

## Rule Engine Tests

Rule engine tests validate direct candidate-to-finding behavior.

Covered areas:

- variable-name rules
- value-pattern rules
- AWS access key matching
- minimum-length behavior
- rule metadata preservation
- confidence metadata
- no-match behavior
- multiple findings from one candidate

Example command:

```bash
pytest tests/test_apply_rules.py
```

---

## CLI Tests

CLI tests run SentinelScan through `subprocess` using the current Python interpreter.

They validate real user-facing behavior, including:

- JSON output
- text output
- severity filtering
- confidence filtering
- redaction
- file ignore behavior
- inline ignore behavior
- invalid CLI choices
- invalid paths
- no-finding behavior

Example command:

```bash
pytest tests/test_cli
```

---

## Continuous Integration

SentinelScan uses GitHub Actions for automated checks.

Workflow file:

```text
.github/workflows/tests.yaml
```

The workflow is expected to:

- check out the repository
- set up Python
- install development dependencies
- run Ruff
- run pytest

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

---

## Testing Guidelines

- Add or update tests with every behavior change.
- Keep feature/refactor tests in the same commit when practical.
- Prefer focused tests over broad tests.
- Use unit tests for internal behavior.
- Use CLI tests for user-facing behavior.
- Keep JSON output tests strict enough to catch schema regressions.
- Keep shared assertions centralized to avoid duplicated test logic.
- Avoid relying on local machine state or untracked files.
