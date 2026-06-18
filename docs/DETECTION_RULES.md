# Detection Rules

SentinelScan detects hardcoded secrets by extracting candidates from Python AST nodes and evaluating them against built-in rules.

---

## Detection Flow

```text
AST syntax → Candidate → Rule engine → Finding
```

Rules can match by:

- suspicious variable/key/keyword names
- structured value patterns
- minimum value length

---

## Built-in Rules

| Rule ID | Severity | Match style |
|---|---|---|
| `AWS_ACCESS_KEY` | HIGH | value matches `AKIA[0-9A-Z]{16}` |
| `PASSWORD` | HIGH | name contains `password`, `pwd`, or `passwd` |
| `API_KEY` | HIGH | name contains `api_key` or `apikey` |
| `TOKEN` | MEDIUM | name contains `token` |
| `SECRET` | MEDIUM | name contains `secret` |

A single candidate can match multiple rules.

---

## Supported Python Syntax

```python
password = "abcdef"
password: str = "abcdef"
self.password = "abcdef"
config["password"] = "abcdef"
config = {"password": "abcdef"}
connect(password="abcdef")
a = password = "abcdef"
```

Only hardcoded string literals are evaluated.

---

## Severity vs Confidence

```text
Severity   = impact if the finding is real
Confidence = likelihood that the value is a real secret
```

Confidence uses placeholder checks, value length, entropy, and value-pattern rules.

---

## Filtering

Severity and confidence filters are exact allow-lists.

```bash
python3 main.py test_dirs --severity HIGH MEDIUM
python3 main.py test_dirs --confidence HIGH
```

`--severity MEDIUM` means `MEDIUM` only, not `MEDIUM` and above.

---

## Output Independence

Rules produce the same `Finding` objects regardless of the selected output format. Text, JSON, and SARIF formatting happen only after rule evaluation, suppression, and severity/confidence filtering.

---

## Limitations

- no variable tracking or data flow
- no taint analysis
- no dynamic execution analysis
- no non-Python file scanning
- unsupported AST shapes are ignored
- false positives and false negatives are possible
