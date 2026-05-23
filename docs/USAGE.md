# Usage Guide

This document covers SentinelScan's command-line usage, output formats, filtering, redaction, and suppression options.

---

## Basic Usage

Scan a directory:

```bash
python3 main.py ./your_directory
```

Scan the included fixture directory:

```bash
python3 main.py test_dirs
```

SentinelScan recursively scans Python files (`.py`) under the provided directory.

---

## CLI Options

```text
path
--json
--severity
--confidence
--redact
```

| Option | Type | Description |
|---|---|---|
| `path` | Required positional argument | Directory to scan |
| `--json` | Boolean flag | Output machine-readable JSON |
| `--severity` | Choice | Show only findings matching a severity |
| `--confidence` | Choice | Show only findings matching a confidence level |
| `--redact` | Boolean flag | Redact detected secret values in output |

Supported severity values:

```text
LOW
MEDIUM
HIGH
```

Supported confidence values:

```text
LOW
MEDIUM
HIGH
```

---

## Human-Readable Output

Default output is human-readable text.

```bash
python3 main.py test_dirs
```

Example:

```text
Scanning 4 Python files...

--- Findings ---

[HIGH] test_dirs/test_repo/open_vulns.py:4 AWS Access Key → AKIAEXAMPLE123456789
Confidence: [HIGH]
Entropy: 3.91
       Reason: value matched AKIA-prefixed AWS access key pattern

[MEDIUM] test_dirs/test_repo/open_vulns.py:5 Token → xyzttttggfdddf
Confidence: [MEDIUM]
Entropy: 3.10
       Reason: variable name matched token pattern and value met minimum length

Total findings: 2
```

Human-readable output includes:

- Scanned file count
- Severity
- File path
- Line number
- Rule name
- Detected or redacted value
- Confidence
- Entropy metadata
- Detection reason
- Total finding count

---

## JSON Output

Use `--json` for machine-readable output.

```bash
python3 main.py test_dirs --json
```

Example:

```json
[
  {
    "line": 4,
    "var_name": "random_var",
    "file": "test_dirs/test_repo/open_vulns.py",
    "rule_id": "AWS_ACCESS_KEY",
    "rule": "AWS Access Key",
    "severity": "HIGH",
    "confidence": "HIGH",
    "entropy": 3.91,
    "value": "AKIAEXAMPLE123456789",
    "reason": "value matched AKIA-prefixed AWS access key pattern"
  }
]
```

JSON mode prints only valid JSON. It does not print scan headers, summaries, or human-readable text.

---

## JSON Fields

| Field | Description |
|---|---|
| `line` | Source line number |
| `var_name` | Extracted variable, attribute, or subscript key |
| `file` | File path |
| `rule_id` | Stable machine-readable rule ID |
| `rule` | Human-readable rule name |
| `severity` | Finding severity |
| `confidence` | Likelihood that the finding is a real secret |
| `entropy` | Entropy score for the detected value |
| `value` | Detected value or redacted value |
| `reason` | Explanation for why the rule matched |

---

## Severity Filtering

Use `--severity` to show only findings matching a selected severity.

```bash
python3 main.py test_dirs --severity HIGH
```

Combine with JSON:

```bash
python3 main.py test_dirs --json --severity HIGH
```

Current built-in rules primarily emit `HIGH` and `MEDIUM` findings. `LOW` is accepted for future compatibility.

---

## Confidence Filtering

Use `--confidence` to show only findings matching a selected confidence level.

```bash
python3 main.py test_dirs --confidence HIGH
```

Combine with JSON:

```bash
python3 main.py test_dirs --json --confidence HIGH
```

Confidence is separate from severity.

```text
Severity   = impact if real
Confidence = likelihood the value is a real secret
```

Example:

```bash
python3 main.py test_dirs --json --severity HIGH --confidence HIGH
```

This shows only findings that are both `HIGH` severity and `HIGH` confidence.

---

## Secret Redaction

Use `--redact` to mask detected values in output.

```bash
python3 main.py test_dirs --redact
```

Redaction is useful when sharing scan output.

### Text Redaction Example

```text
[HIGH] test_dirs/test_repo/example.py:1 Password → a****f
Confidence: [LOW]
Entropy: 2.58
       Reason: variable name matched password/pwd/passwd pattern and value met minimum length
```

### JSON Redaction Example

```bash
python3 main.py test_dirs --json --redact
```

```json
[
  {
    "line": 1,
    "var_name": "password",
    "file": "test_dirs/test_repo/example.py",
    "rule_id": "PASSWORD",
    "rule": "Password",
    "severity": "HIGH",
    "confidence": "LOW",
    "entropy": 2.58,
    "value": "a****f",
    "reason": "variable name matched password/pwd/passwd pattern and value met minimum length"
  }
]
```

### Redaction Behavior

| Original Value | Redacted Value |
|---|---|
| `abcd` | `[REDACTED]` |
| `abcdef` | `a****f` |
| `abc_def-123#$%^&*()` | `ab***************()` |
| `AKIAEXAMPLE123456789` | `AK****************89` |

Redaction notes:

- Empty or very short values are fully redacted.
- Medium values preserve limited prefix/suffix context.
- Longer values preserve the first two and last two characters.
- Redaction happens only during output formatting.
- Detection still uses the original extracted value.

---

## Combined Flags

SentinelScan supports combining output format, filtering, and redaction.

```bash
python3 main.py test_dirs --json --severity HIGH --confidence HIGH --redact
```

This command:

1. Scans `test_dirs`
2. Keeps only `HIGH` severity findings
3. Keeps only `HIGH` confidence findings
4. Redacts detected values
5. Outputs valid JSON

---

## Supported Detection Examples

SentinelScan detects hardcoded string values in supported assignment patterns.

### Simple Assignments

```python
password = "abcdef"
api_key = "abc1234567890j"
token = "abc1234567890j"
```

### Attribute Assignments

```python
self.password = "abcdef"
settings.auth.credentials.api_key = "abc1234567890j"
```

### Subscript Assignments

```python
config["password"] = "abcdef"
settings["api_key"] = "abc1234567890j"
config["auth"]["token"] = "abc1234567890j"
```

Unsupported examples:

```python
password = "abc" + "def"
password = os.getenv("PASSWORD")
config[dynamic_key] = "abcdef"
items[0] = "abcdef"
```

---

## `.sentinelscanignore`

Use `.sentinelscanignore` to skip files or directories before scanning.

Example:

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
- Parent `.sentinelscanignore` files can apply to child scan paths

Example:

```bash
python3 main.py .
```

If `.sentinelscanignore` contains:

```text
test_dirs/
```

then files inside `test_dirs/` are skipped.

---

## Inline Ignores

Inline ignores suppress findings on specific source lines.

### Generic Inline Ignore

```python
password = "fakepassword"  # sentinelscan: ignore
```

Suppresses all findings on that line.

### Rule-Specific Inline Ignore

```python
api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY
```

Suppresses only the listed rule ID.

In this example:

```text
AWS_ACCESS_KEY → suppressed
API_KEY        → still reported
```

Suppress multiple rules:

```python
api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY API_KEY
```

Inline ignore markers must appear inside Python comments. This does not suppress findings:

```python
password = "sentinelscan: ignore"
```

---

## No Findings

Text mode:

```text
No vulnerabilities found.
```

JSON mode:

```json
[]
```

---

## Invalid Inputs

Invalid paths produce a user-facing error.

```bash
python3 main.py does_not_exist
```

Example output:

```text
[ERROR] 'does_not_exist' does not exist or is not a directory!
```

Invalid option values are rejected by `argparse`.

```bash
python3 main.py test_dirs --severity CRITICAL
```

```text
invalid choice
```

---

## Current Scope

SentinelScan currently scans Python files and evaluates hardcoded string literal assignments.

It is not currently a full data-flow or taint-analysis engine.
