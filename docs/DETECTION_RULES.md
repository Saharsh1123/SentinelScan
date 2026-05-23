# Detection Rules

This document explains SentinelScan's rule engine, built-in rules, supported assignment patterns, detection reasons, confidence scoring, and limitations.

---

## Detection Flow

```text
Candidate → apply rules → Finding
```

Rules can match using:

1. Variable name patterns
2. Value patterns
3. Minimum value length

The AST analyzer extracts candidates. The rule engine evaluates candidates and returns structured findings.

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

These rules match suspicious variable names when the assigned string value meets the minimum length.

```python
password = "abcdef"
pwd = "abcdef"
passwd = "abcdef"
api_key = "12345678"
apikey = "12345678"
token = "qwerty123"
client_secret = "abcdef"
```

Supported forms:

```python
self.password = "abcdef"
self.config.db.password = "abcdef"
config["password"] = "abcdef"
settings["api_key"] = "abc1234567890j"
```

Short values are ignored:

```python
password = "abc"
```

---

## Value-Pattern Detection

Some rules match the value itself.

```python
random_var = "AKIAEXAMPLE123456789"
```

This can be flagged as `AWS_ACCESS_KEY` even if the variable name is not suspicious.

---

## Multiple Classifications

One assignment can trigger multiple rules.

```python
api_key = "AKIAEXAMPLE123456789"
```

Possible findings:

```text
AWS_ACCESS_KEY
API_KEY
```

Reasons:

- The value matches the AWS access key pattern
- The variable name matches the API key pattern

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

## Supported Assignment Patterns

### Simple Variables

```python
password = "abcdef"
api_key = "12345678"
token = "abc1234567890j"
secret = "abcdef"
```

### Attributes

```python
self.password = "abcdef"
config.api_key = "12345678"
user.token = "abc1234567890j"
```

### Nested Attributes

```python
self.config.db.password = "abcdef"
settings.auth.credentials.api_key = "12345678"
```

The final attribute name is used.

### Subscripts

```python
config["password"] = "abcdef"
settings["api_key"] = "abc1234567890j"
secrets["token"] = "abc1234567890j"
config["auth"]["password"] = "abcdef"
```

The final string key is used.

### Multiple Targets

```python
a = password = "abcdef"
password = token = "abcdef"
config["password"] = settings["token"] = "abcdef"
```

Each sensitive target can produce a finding.

---

## Ignored Patterns

SentinelScan ignores unsupported or low-signal patterns.

```python
password = 123456
config[password_key] = "abcdef"
items[0] = "abcdef"
password = os.getenv("PASSWORD")
password = input("Enter password: ")
password = "abc" + "def"
```

Currently ignored cases:

- Non-string assigned values
- Dynamic subscript keys
- Numeric subscript indexes
- Function call return values
- Function call arguments
- String concatenation
- Dynamically constructed values
- Non-Python files

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

AWS access key findings are high-confidence because the pattern is specific.

---

## Entropy Metadata

Each finding includes entropy metadata.

Entropy estimates how random-looking a value is. It is used for confidence scoring and included in JSON output.

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

Filtering controls displayed findings only.

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

Short values:

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

Multiple rules:

```python
api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore AWS_ACCESS_KEY API_KEY
```

Inline ignore markers must appear inside Python comments.

This does not suppress findings:

```python
password = "sentinelscan: ignore"
```

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
config = {"password": "abcdef"}
password = os.getenv("PASSWORD")
```

Future improvements may reduce these through dictionary extraction, function-call extraction, constant propagation, data-flow analysis, and additional file type support.

---

## Current Scope

SentinelScan currently focuses on:

```text
Python source files
AST-based assignment analysis
Hardcoded string literals
Rule-based secret detection
Confidence scoring
Structured text/JSON output
```

It is not a full data-flow or taint-analysis engine yet.
