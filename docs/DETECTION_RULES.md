# Detection Rules

This document explains SentinelScan's rule engine, built-in rules, supported assignment patterns, detection reasons, and known detection limitations.

---

## Detection Engine Overview

SentinelScan uses a modular rule engine.

The detection process is:

```text
Candidate → apply rules → Finding
```

Rules can match based on:

1. Variable name patterns
2. Value patterns
3. Minimum value length

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

## Detection Types

### Variable-Name-Based Detection

These rules detect secrets based on suspicious variable names plus minimum value length.

Examples:

```python
password = "abcdef"
pwd = "abcdef"
passwd = "abcdef"
self.config.db.password = "abcdef"
api_key = "12345678"
apikey = "12345678"
token = "qwerty123"
client_secret = "abcdef"
```

These rules reduce obvious false positives by requiring the string value to meet the configured minimum length.

### Value-Pattern-Based Detection

These rules detect secrets based on the value itself.

Example:

```python
random_var = "AKIAEXAMPLE123456789"
```

This can still be flagged as an AWS access key even if the variable name is not suspicious.

---

## Multiple Classifications

Some assignments can match more than one rule.

Example:

```python
api_key = "AKIAEXAMPLE123456789"
```

This may produce two findings:

```text
AWS_ACCESS_KEY
API_KEY
```

because:

- The value matches the AWS access key pattern
- The variable name matches the API key pattern

---

## Detection Reasons

Every finding includes a reason explaining why it was flagged.

Current reason strings include:

```text
value matched AKIA-prefixed AWS access key pattern
variable name matched password/pwd/passwd pattern and value met minimum length
variable name matched api_key/apikey pattern and value met minimum length
variable name matched token pattern and value met minimum length
variable name matched secret pattern and value met minimum length
```

Reasons are included in both text and JSON output.

---

## Supported Assignment Patterns

SentinelScan currently supports simple Python assignment patterns.

Supported examples:

```python
password = "abcdef"
self.password = "abcdef"
self.config.db.password = "abcdef"
a = password = "abcdef"
password = token = "abcdef"
api_key = "AKIAEXAMPLE123456789"
```

### Simple Variables

```python
password = "abcdef"
token = "qwerty123"
```

### Object Attributes

```python
self.password = "abcdef"
config.api_key = "12345678"
```

### Nested Attributes

```python
self.config.db.password = "abcdef"
settings.auth.credentials.api_key = "12345678"
```

### Multiple Assignment Targets

```python
a = password = "abcdef"
password = token = "abcdef"
```

---

## Unsupported Assignment Patterns

SentinelScan intentionally ignores unsupported or non-string assignments such as:

```python
password = 123456
config["password"] = "abcdef"
password = os.getenv("PASSWORD")
password = input("Enter password: ")
```

Currently unsupported cases include:

- Dictionary/subscript assignments
- Function-call arguments
- Return values
- String concatenation
- Environment variable loading
- Dynamically constructed values
- Non-Python files

---

## False Positives and False Negatives

SentinelScan uses rule-based static analysis. It may still produce false positives or false negatives.

Examples of possible false positives:

```python
password = "not actually a real password"
token = "example"
```

Examples of possible false negatives:

```python
config["password"] = "abcdef"
password = "abc" + "def"
set_password("abcdef")
```

Future improvements may reduce these limitations through entropy scoring, confidence scoring, additional AST node support, and data-flow analysis.

---

## Redaction and Detection

Redaction does not affect detection.

The rule engine always evaluates the original extracted value. Redaction is applied later during output formatting.

This means:

```text
original value → rule engine
redacted value → CLI/JSON output only when --redact is used
```
