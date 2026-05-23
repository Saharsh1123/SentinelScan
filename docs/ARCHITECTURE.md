# Architecture

SentinelScan is a Python CLI static-analysis tool for finding hardcoded secrets in Python source files. It uses AST-based extraction, modular detection rules, entropy/confidence scoring, suppression logic, and structured text/JSON output.

---

## Pipeline

```text
CLI arguments
→ path validation
→ .sentinelscanignore discovery
→ Python file discovery
→ file ignore filtering
→ file reading
→ AST parsing
→ candidate extraction
→ rule evaluation
→ finding creation
→ inline ignore filtering
→ file path attachment
→ severity/confidence filtering
→ output formatting
```

---

## Design Principles

| Area | Responsibility |
|---|---|
| AST analyzer | Extract possible candidates |
| Rule engine | Convert matching candidates into findings |
| Scanner | Handle file paths, file reading, and source-line suppression |
| Output layer | Handle filtering, redaction, text output, and JSON output |
| Ignore system | Skip files before scanning |
| Inline ignore system | Suppress findings after detection |

This separation keeps extraction, detection, suppression, filtering, and presentation independent.

---

## Core Data Models

### `Rule`

Represents one detection rule.

```text
rule_id
rule_name
severity
reason
var_patterns
value_pattern
min_length
```

Examples:

```text
PASSWORD
API_KEY
TOKEN
SECRET
AWS_ACCESS_KEY
```

### `Candidate`

Represents extracted source-code data that may be suspicious.

```text
line_number
var_name
value
```

Example:

```python
config["api_key"] = "abc1234567890j"
```

Candidate:

```text
line_number = 1
var_name = "api_key"
value = "abc1234567890j"
```

### `Finding`

Represents a confirmed rule match.

```text
file_path
line_number
var_name
value
rule_id
rule_name
severity
reason
confidence
entropy
```

Findings are used by filtering, redaction, JSON output, text output, inline ignore suppression, and tests.

---

## Candidate vs Finding

| Object | Meaning | Created by |
|---|---|---|
| `Candidate` | Extracted value that may match a rule | AST analyzer |
| `Finding` | Confirmed rule match | Rule engine |

Example:

```python
username = "abcdef"
```

This may become a candidate, but should not become a finding.

```python
password = "abcdef"
```

This becomes:

```text
Candidate → rule match → Finding
```

---

## Supported AST Extraction

SentinelScan currently evaluates hardcoded string literal assignments.

### Simple Assignments

```python
password = "abcdef"
api_key = "abc1234567890j"
token = "abc1234567890j"
```

### Attribute Assignments

```python
self.password = "abcdef"
config.api_key = "abc1234567890j"
settings.auth.credentials.api_key = "abc1234567890j"
```

The final attribute name is used.

### Subscript Assignments

```python
config["password"] = "abcdef"
settings["api_key"] = "abc1234567890j"
secrets["token"] = "abc1234567890j"
config["auth"]["password"] = "abcdef"
```

The final string key is used.

Unsupported subscript examples:

```python
config[password_key] = "abcdef"
items[0] = "abcdef"
```

These are ignored because the key is not a string literal.

---

## Confidence and Entropy

SentinelScan tracks both severity and confidence.

| Signal | Meaning |
|---|---|
| Severity | Impact if the finding is real |
| Confidence | Likelihood that the value is a real secret |

Confidence uses:

- Value length
- Shannon entropy
- Common/test value heuristics
- Strong value-pattern matches

Examples:

| Value | Expected Confidence |
|---|---|
| `abcdef` | `LOW` |
| `xyzttttggfdddf` | `MEDIUM` |
| `abc1234567890j` | `HIGH` |
| `AKIAEXAMPLE123456789` | `HIGH` |

Entropy is stored on each finding as metadata.

---

## Filtering

Severity filter:

```bash
python3 main.py path/to/project --severity HIGH
```

Confidence filter:

```bash
python3 main.py path/to/project --confidence HIGH
```

Combined:

```bash
python3 main.py path/to/project --severity HIGH --confidence HIGH
```

Filtering controls displayed findings. It does not change detection.

---

## Redaction

Redaction is applied only during output formatting.

```bash
python3 main.py path/to/project --redact
```

Example:

```text
abc1234567890j → ab**********0j
```

Short values are fully redacted:

```text
[REDACTED]
```

The rule engine always evaluates the original value.

---

## Suppression Systems

| System | Applies When | Purpose |
|---|---|---|
| `.sentinelscanignore` | Before scanning | Skip files/directories |
| Inline ignores | After detection | Suppress findings on specific lines |

---

## `.sentinelscanignore`

`.sentinelscanignore` is a plain text pattern file.

```text
venv/
__pycache__/
test_dirs/
*.min.py
ignored.py
```

Supported behavior:

- Blank lines are ignored
- Comment lines are ignored
- Directory patterns are supported
- Filename patterns are supported
- Glob patterns are supported
- Parent ignore files can apply to child scan paths

Implementation:

```text
ignore.py
```

---

## Inline Ignores

Generic inline ignore:

```python
password = "fakepassword"  # sentinelscan: ignore
```

Suppresses all findings on that line.

Rule-specific inline ignore:

```python
api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY
```

Suppresses only the listed rule.

Example result:

```text
AWS_ACCESS_KEY → suppressed
API_KEY        → still reported
```

Multiple rules:

```python
api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY API_KEY
```

Inline ignore detection checks Python comment tokens, so this does not suppress findings:

```python
password = "sentinelscan: ignore"
```

Implementation:

```text
inline_ignore.py
```

---

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `cli.py` | Parse command-line arguments |
| `main.py` | Orchestrate scan flow |
| `scanner.py` | Validate paths, discover/read files, apply inline ignores, attach file paths |
| `ignore.py` | Load and apply `.sentinelscanignore` patterns |
| `inline_ignore.py` | Detect generic and rule-specific inline ignores |
| `output.py` | Filter, redact, format, and serialize findings |
| `detectors/ast_analyzer.py` | Parse AST and extract candidates |
| `detectors/confidence.py` | Calculate entropy and confidence |
| `detectors/models.py` | Define dataclasses |
| `detectors/rules.py` | Define built-in rules |
| `detectors/rule_engine.py` | Apply rules to candidates |
| `detectors/find_secrets.py` | Coordinate candidate extraction and rule evaluation |

---

## Test Layout

```text
tests/
├── test_ast/
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
├── helpers.py
├── test_apply_rules.py
├── test_confidence.py
├── test_ignore.py
└── test_inline_ignore.py
```

---

## Current Limitations

- Only Python files are scanned
- Only string literal assignments are evaluated
- Function call arguments are not fully analyzed yet
- Dictionary literal contents are not fully analyzed yet
- Environment files such as `.env` are not scanned yet
- No multi-file data flow analysis yet
- No taint analysis yet
- No SARIF output yet
- No installable package entry point yet
- Config support is not fully implemented yet

---

## Future Architecture Directions

Likely future modules:

```text
config.py
sarif.py
reporting.py
file_types/
dataflow.py
taint.py
```

Likely next milestones:

1. JSON config support
2. Rule disabling through config
3. Dictionary literal extraction
4. Function-call keyword argument extraction
5. SARIF output
6. Package metadata and console script entry point
