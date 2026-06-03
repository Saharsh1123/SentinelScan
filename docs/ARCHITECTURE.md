# Architecture

SentinelScan is a Python CLI static-analysis tool for finding hardcoded secrets in Python source files. It separates file handling, AST extraction, rule evaluation, suppression, filtering, and output formatting so new detection behavior can be added without rewriting the whole scanner.

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

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `cli.py` | Define and parse CLI arguments |
| `main.py` | Coordinate the scan pipeline |
| `scanner.py` | Validate paths, discover files, read files, apply inline ignores, and attach file paths |
| `ignore.py` | Load and apply `.sentinelscanignore` patterns |
| `inline_ignore.py` | Detect generic and rule-specific inline ignores from Python comments |
| `output.py` | Filter, redact, format, and serialize findings |
| `detectors/ast_analyzer.py` | Parse AST and extract normalized candidates |
| `detectors/find_secrets.py` | Connect candidate extraction to rule evaluation |
| `detectors/rule_engine.py` | Apply built-in rules and create findings |
| `detectors/rules.py` | Define built-in rules |
| `detectors/confidence.py` | Calculate entropy and confidence metadata |
| `detectors/models.py` | Define `Rule`, `Candidate`, and `Finding` dataclasses |

---

## Core Models

### `Rule`

A declarative detection rule.

```text
rule_id
rule_name
severity
reason
var_patterns
value_pattern
min_length
```

### `Candidate`

A normalized value extracted from source code before rule evaluation.

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

A confirmed rule match.

```text
file_path
line_number
var_name
value
rule_id
rule_name
severity
reason
entropy
confidence
```

Findings are used by filtering, redaction, JSON output, text output, inline ignore suppression, and tests.

---

## Candidate vs Finding

| Object | Meaning | Created by |
|---|---|---|
| `Candidate` | Extracted value that may be suspicious | AST analyzer |
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

SentinelScan currently evaluates hardcoded string literals in supported Python syntax shapes.

### Simple Assignments

```python
password = "abcdef"
api_key = "abc1234567890j"
token = "abc1234567890j"
```

### Annotated Assignments

```python
password: str = "abcdef"
api_key: str = "abc1234567890j"
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
config["auth"]["password"] = "abcdef"
```

The final string key is used.

### Dictionary Literals

```python
config = {
    "password": "abcdef",
    "api_key": "abc1234567890j",
}
```

The string key becomes the candidate name and the string value becomes the candidate value.

### Multiple Assignment Targets

```python
a = password = "abcdef"
password = token = "abcdef"
config["password"] = settings["token"] = "abcdef"
```

Each supported target can produce a candidate.

---

## Suppression Systems

| System | Applies When | Purpose |
|---|---|---|
| `.sentinelscanignore` | Before scanning | Skip files/directories |
| Inline ignores | After detection | Suppress findings on specific lines |

Inline ignores are parsed from Python comments using `tokenize`, so string literals containing `sentinelscan: ignore` do not suppress findings accidentally.

---

## Severity, Entropy, and Confidence

SentinelScan separates severity from confidence.

```text
Severity   = impact if the finding is real
Confidence = likelihood that the value is a real secret
```

Confidence uses:

- value length
- Shannon entropy
- common/test value heuristics
- strong value-pattern matches

Entropy is stored on findings and included in JSON output.

---

## Design Guidelines

- AST extraction should produce candidates, not findings.
- Rule evaluation should produce findings, not print output.
- Scanner code should handle files and suppression, not rule logic.
- Output code should format/redact/filter findings, not run detection.
- Redaction should happen only during output rendering.
- JSON output should remain machine-readable and free of text headers.

---

## Current Limitations

- Only Python files are scanned.
- Only supported hardcoded string-literal syntax is analyzed.
- Function-call arguments are not analyzed yet.
- Return statements are not analyzed yet.
- Values are not followed across variables yet.
- No multi-file data-flow analysis yet.
- No taint analysis yet.
- No SARIF output yet.
- No installable console script yet.

---

## Likely Future Modules

```text
config.py
sarif.py
reporting.py
file_types/
dataflow.py
taint.py
```
