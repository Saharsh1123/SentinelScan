# Architecture

This document explains SentinelScan's internal architecture, data flow, and module responsibilities.

---

## High-Level Pipeline

SentinelScan follows a staged pipeline:

```text
file discovery
→ file reading
→ AST parsing
→ candidate extraction
→ rule evaluation
→ finding creation
→ file path attachment
→ severity filtering
→ output formatting
```

Detailed flow:

1. Parse CLI arguments with `argparse`
2. Validate that the provided path is a directory
3. Recursively discover Python files
4. Read each Python file safely
5. Parse source code into a Python AST
6. Find assignment nodes
7. Extract string literal assignment values
8. Extract variable paths from simple variables and nested attributes
9. Create `Candidate` objects from extracted AST data
10. Apply modular rules to each candidate
11. Create `Finding` objects for confirmed matches
12. Attach file paths in the scanner layer
13. Apply optional severity filtering
14. Output results as human-readable text or JSON
15. Apply optional redaction only during output formatting

---

## Design Goals

SentinelScan is designed around separation of concerns:

| Layer | Responsibility |
|---|---|
| CLI | Parse user input |
| Scanner | Handle files and paths |
| AST analyzer | Extract candidates from Python code |
| Rule engine | Apply rules to candidates |
| Models | Define shared structured data |
| Output | Format findings as text or JSON |

This prevents extraction, detection, filtering, and formatting logic from becoming tangled.

---

## Core Data Models

SentinelScan uses dataclasses to avoid fragile tuple-based data flow.

### `Rule`

A `Rule` represents one detection rule.

Conceptually stores:

```text
rule_id
rule_name
severity
reason
var_patterns
value_pattern
min_length
```

Rules are defined once and reused by the rule engine.

### `Candidate`

A `Candidate` represents extracted source-code data that might be suspicious.

Conceptually stores:

```text
line_number
var_name
value
```

Candidates are created before rule evaluation.

Example source:

```python
self.config.password = "abcdef"
```

Candidate:

```text
line_number = 1
var_name = "password"
value = "abcdef"
```

### `Finding`

A `Finding` represents a confirmed detection.

Conceptually stores:

```text
file_path
line_number
var_name
value
rule_id
rule_name
severity
reason
```

Findings are used by filtering, JSON output, text output, and tests.

---

## Candidate vs Finding

Candidates and findings are intentionally separate.

| Object | Meaning | Created by |
|---|---|---|
| `Candidate` | Extracted value that might match a rule | AST analyzer |
| `Finding` | Confirmed rule match | Rule engine |

Example:

```python
username = "abcdef"
```

This may become a `Candidate`, but it should not become a `Finding` if no rule matches.

Example:

```python
password = "abcdef"
```

This becomes:

```text
Candidate → rule match → Finding
```

---

## Module Responsibilities

### `cli.py`

Handles command-line argument parsing.

Current CLI options include:

```text
path
--json
--severity
--redact
```

### `main.py`

Acts as the CLI entry point.

Responsible for orchestrating:

```text
CLI args
→ path validation
→ file discovery
→ scanning
→ filtering
→ output
```

### `scanner.py`

Handles file-system level scanning work:

- Validates input paths
- Recursively finds Python files
- Reads file contents safely
- Calls the detector
- Attaches file paths to findings

Scanner is the correct layer for file paths because it knows which file is being read.

### `output.py`

Handles output-specific behavior:

- Severity filtering
- JSON serialization
- Human-readable text formatting
- Secret redaction

Redaction belongs in the output layer because the rule engine should preserve original values internally.

### `detectors/ast_analyzer.py`

Handles Python AST parsing and candidate extraction.

Responsible for:

- Parsing code
- Finding assignment nodes
- Extracting string literal values
- Extracting simple and nested variable names
- Creating candidate objects

### `detectors/models.py`

Defines structured dataclass models used across the scanner:

- `Rule`
- `Candidate`
- `Finding`

### `detectors/rules.py`

Contains built-in rule definitions.

Rules are data-driven and include:

- Rule ID
- Rule name
- Severity
- Reason
- Variable-name regex patterns
- Optional value regex patterns
- Optional minimum length

### `detectors/rule_engine.py`

Applies rules to candidates.

Responsible for:

- Checking value-pattern-based rules
- Checking variable-name-based rules
- Creating finding objects
- Returning structured findings

### `detectors/find_secrets.py`

Coordinates AST extraction and rule evaluation.

Responsible for:

```text
code string → candidates → findings
```

---

## Why Dataclasses

Earlier versions used tuples such as:

```text
(line_number, file_path, rule_name, severity, value, reason)
```

That became fragile because adding one field required changing tuple unpacking across multiple modules.

Dataclasses make the data flow clearer:

```text
finding.line_number
finding.file_path
finding.rule_name
finding.severity
finding.value
finding.reason
```

Benefits:

- Clearer field names
- Easier refactoring
- Cleaner tests
- Less tuple-order fragility
- Better editor autocomplete
- Easier JSON conversion

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
