# Usage Guide

This document covers SentinelScan's command-line usage, output formats, severity filtering, and secret redaction.

---

## Basic Usage

Scan a directory:

```bash
python3 main.py ./your_directory
```

Scan the included test fixture directory:

```bash
python3 main.py test_dirs
```

SentinelScan recursively scans Python files (`.py`) under the provided directory.

---

## CLI Options

Current CLI options:

```text
path
--json
--severity
--redact
```

| Option | Type | Description |
|---|---|---|
| `path` | Required positional argument | Directory to scan |
| `--json` | Boolean flag | Output machine-readable JSON |
| `--severity` | Choice | Filter findings by severity |
| `--redact` | Boolean flag | Redact detected secret values in output |

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

[HIGH] test_dirs/edge_repo/edge_test.py:1 Password → hjkl
       Reason: variable name matched password/pwd/passwd pattern and value met minimum length

[HIGH] test_dirs/test_repo/open_vulns.py:4 AWS Access Key → AKIAEXAMPLE123456789
       Reason: value matched AKIA-prefixed AWS access key pattern

[MEDIUM] test_dirs/test_repo/open_vulns.py:5 Token → xyzttttggfdddf
       Reason: variable name matched token pattern and value met minimum length

Total findings: 6
```

Human-readable output includes:

- Scanned file count
- Finding severity
- File path
- Line number
- Rule name
- Detected value
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
    "line": 1,
    "file": "test_dirs/edge_repo/edge_test.py",
    "var_name": "password",
    "rule_id": "PASSWORD",
    "rule": "Password",
    "severity": "HIGH",
    "value": "hjkl",
    "reason": "variable name matched password/pwd/passwd pattern and value met minimum length"
  },
  {
    "line": 4,
    "file": "test_dirs/test_repo/open_vulns.py",
    "var_name": "random_var",
    "rule_id": "AWS_ACCESS_KEY",
    "rule": "AWS Access Key",
    "severity": "HIGH",
    "value": "AKIAEXAMPLE123456789",
    "reason": "value matched AKIA-prefixed AWS access key pattern"
  }
]
```

JSON mode prints only valid JSON. It does not print CLI headers, summaries, or extra human-readable text.

### JSON Fields

| Field | Description |
|---|---|
| `line` | Source line number |
| `file` | File path |
| `var_name` | Extracted variable or final attribute name |
| `rule_id` | Stable machine-readable rule ID |
| `rule` | Human-readable rule name |
| `severity` | Finding severity |
| `value` | Detected value or redacted value |
| `reason` | Explanation for why the rule matched |

---

## Severity Filtering

Use `--severity` to filter findings by severity.

```bash
python3 main.py test_dirs --severity HIGH
```

Combine severity filtering with JSON:

```bash
python3 main.py test_dirs --json --severity HIGH
```

The CLI accepts:

```text
LOW
MEDIUM
HIGH
```

Current built-in rules emit `HIGH` and `MEDIUM` findings. A `LOW` filter may return no findings unless future rules emit `LOW`.

---

## Secret Redaction

Use `--redact` to mask detected secret values.

```bash
python3 main.py test_dirs --redact
```

Redaction is useful when sharing scan output because normal output may include detected values directly.

### Text Redaction Example

```text
[HIGH] test_dirs/test_repo/example.py:1 Password → a****f
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
    "file": "test_dirs/test_repo/example.py",
    "var_name": "password",
    "rule_id": "PASSWORD",
    "rule": "Password",
    "severity": "HIGH",
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

Notes:

- Empty or very short values are fully redacted as `[REDACTED]`
- Medium values preserve limited prefix/suffix context
- Longer values preserve the first two and last two characters
- Redaction happens only during output formatting
- Internal detection still uses the original extracted value

---

## Combined Flags

SentinelScan supports combining output format, filtering, and redaction.

```bash
python3 main.py test_dirs --json --severity HIGH --redact
```

This command:

1. Scans `test_dirs`
2. Keeps only `HIGH` severity findings
3. Redacts detected values
4. Outputs valid JSON

---

## No Findings

When no vulnerabilities are found in text mode, SentinelScan prints:

```text
No vulnerabilities found.
```

In JSON mode, no findings are represented as:

```json
[]
```

---

## Invalid Inputs

Invalid paths are handled with a user-facing error message.

Example:

```bash
python3 main.py does_not_exist
```

The output includes an error message such as:

```text
[ERROR] 'does_not_exist' does not exist or is not a directory!
```
