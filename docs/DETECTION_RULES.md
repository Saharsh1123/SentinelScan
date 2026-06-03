# Detection Rules

This document explains SentinelScan's rule engine, built-in rules, supported syntax, confidence scoring, suppression behavior, and current limitations.

---

## Detection Flow

```text
AST syntax → Candidate → Rule engine → Finding
```

The AST analyzer extracts candidates. The rule engine evaluates candidates with built-in rules and returns structured findings.

Rules can match using:

1. variable-name patterns
2. value patterns
3. minimum value length

---

## Built-In Rules

| Rule ID | Rule Name | Severity | Detection Type |
|---|---|---:|---|
| `AWS_ACCESS_KEY` | AWS Access Key | `HIGH` | Value pattern |
| `PASSWORD` | Password | `HIGH` | Variable name + minimum length |
| `API_KEY` | API Key | `HIGH` | Variable name + minimum length |
| `TOKEN` | Token | `MEDIUM` | Variable name + minimum length |
| `SECRET` | Secret | `MEDIUM` | Variable name + minimum length |

---

## Variable-Name Detection

These rules match suspicious names when the extracted string value meets the minimum length.

```python
password = "abcdef"
pwd = "abcdef"
passwd = "abcdef"
api_key = "12345678"
apikey = "12345678"
token = "qwerty123"
client_secret = "abcdef"
```

Short values are ignored:

```python
password = "abc"
```

---

## Value-Pattern Detection

Some rules match the value itself, regardless of variable name.

```python
random_var = "AKIAEXAMPLE123456789"
```

This can be flagged as `AWS_ACCESS_KEY` even if `random_var` is not suspicious.

---

## Multiple Classifications

One candidate can trigger multiple rules.

```python
api_key = "AKIAEXAMPLE123456789"
```

Possible findings:

```text
AWS_ACCESS_KEY
API_KEY
```

Reasons:

- The value matches the AWS access key pattern.
- The variable name matches the API key pattern.

---

## Supported Syntax

### Simple Assignments

```python
password = "abcdef"
api_key = "abc1234567890j"
token = "abc1234567890j"
secret = "abcdef"
```

### Annotated Assignments

```python
password: str = "abcdef"
api_key: str = "abc1234567890j"
```

Bare annotations without assigned values are ignored:

```python
password: str
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

### Dictionary Literals

```python
config = {
    "password": "abcdef",
    "api_key": "abc1234567890j",
    "token": "abc1234567890j",
}
```

For dictionary literals, the string key becomes the candidate name and the string value becomes the candidate value.

Unsupported dictionary entries:

```python
config = {password_key: "abcdef"}
config = {"password": 123456}
```

These are ignored because the key or value is not a string literal.

### Multiple Targets

```python
a = password = "abcdef"
password = token = "abcdef"
config["password"] = settings["token"] = "abcdef"
```

Each supported target can produce a candidate.

---

## Detection Reasons

Each finding includes a reason.

```text
value matched AKIA-prefixed AWS access key pattern
variable name matched password/pwd/passwd pattern and value met minimum length
variable name matched api_key/apikey pattern and value met minimum length
variable name matched token pattern and value met minimum length
variable name matched secret pattern and value met minimum length
```

Reasons are included in text and JSON output.

---

## Confidence Scoring

SentinelScan tracks confidence separately from severity.

| Signal | Meaning |
|---|---|
| Severity | Impact if the finding is real |
| Confidence | Likelihood that the value is a real secret |

Confidence levels:

```text
LOW
MEDIUM
HIGH
```

Confidence uses:

- value length
- Shannon entropy
- common/test value heuristics
- strong value-pattern matches

Examples:

| Value | Expected Confidence |
|---|---|
| `abcdef` | `LOW` |
| `xyzttttggfdddf` | `MEDIUM` |
| `abc1234567890j` | `HIGH` |
| `AKIAEXAMPLE123456789` | `HIGH` |

AWS access key findings are high-confidence because the value pattern is specific.

---

## Entropy Metadata

Each finding includes entropy metadata. Entropy estimates how random-looking a value is. It is used for confidence scoring and included in JSON output.

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

Filtering controls displayed findings only. It does not change detection.

---

## Redaction

Redaction does not affect detection.

```text
original value → rule engine
redacted value → output only
```

Example:

```bash
python3 main.py path/to/project --redact
```

```text
abc1234567890j → ab**********0j
```

Short values are fully redacted:

```text
[REDACTED]
```

---

## Suppression

### `.sentinelscanignore`

Skips files and directories before scanning.

```text
venv/
__pycache__/
test_dirs/
*.min.py
ignored.py
```

### Generic Inline Ignore

Suppresses all findings on a line.

```python
password = "fakepassword"  # sentinelscan: ignore
```

### Rule-Specific Inline Ignore

Suppresses selected rule IDs.

```python
api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY
```

Result:

```text
AWS_ACCESS_KEY → suppressed
API_KEY        → still reported
```

Inline ignore markers must appear inside Python comments. This does not suppress findings:

```python
password = "sentinelscan: ignore"
```

---

## Ignored Patterns

SentinelScan intentionally ignores unsupported or lower-signal patterns.

```python
password = 123456
config[password_key] = "abcdef"
items[0] = "abcdef"
password = os.getenv("PASSWORD")
password = input("Enter password: ")
password = "abc" + "def"
set_password("abcdef")
return "abcdef"
```

Currently ignored areas include:

- non-string assigned values
- dynamic subscript keys
- numeric subscript indexes
- function call return values
- function call arguments
- return statements
- string concatenation
- dynamically constructed values
- non-Python files

---

## False Positives and False Negatives

Possible false positives:

```python
password = "not actually a real password"
token = "example_value_123"
client_secret = "fake_for_testing"
```

Possible false negatives:

```python
password = "abc" + "def"
set_password("abcdef")
return "abcdef"
password = os.getenv("PASSWORD")
```

Future improvements may reduce these through function-call extraction, constant propagation, data-flow analysis, and additional file type support.

---

## Current Scope

SentinelScan currently focuses on:

```text
Python source files
AST-based string-literal analysis
Rule-based hardcoded-secret detection
Confidence scoring
Structured text/JSON output
```

It is not a full data-flow or taint-analysis engine yet.
