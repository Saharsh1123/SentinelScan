# Usage Guide

This guide covers SentinelScan's CLI options, config lookup, output formats, filtering, redaction, and suppression.

---

## Basic Usage

```bash
python3 main.py ./your_directory
python3 main.py test_dirs
```

SentinelScan recursively scans Python files under the provided directory.

---

## CLI Options

| Option | Description |
|---|---|
| `path` | Directory to scan |
| `--format text/json/sarif` | Select the output format |
| `--severity LOW MEDIUM HIGH` | Keep exact severity levels |
| `--confidence LOW MEDIUM HIGH` | Keep exact confidence levels |
| `--redact` | Mask detected values in text and JSON output |

Severity and confidence values are exact selections, not thresholds.

```bash
python3 main.py test_dirs --severity HIGH
python3 main.py test_dirs --severity HIGH MEDIUM
python3 main.py test_dirs --confidence HIGH LOW
```

---

## Config File

SentinelScan checks config locations in this order:

1. `<scan-root>/sentinelscan.json`
2. `./sentinelscan.json` in the current working directory
3. built-in defaults

```json
{
  "severity_levels": ["HIGH", "MEDIUM"],
  "confidence_levels": ["HIGH"],
  "redact": true,
  "output_format": "sarif"
}
```

Supported fields:

| Field | Type | Allowed values |
|---|---|---|
| `severity_levels` | list | `LOW`, `MEDIUM`, `HIGH` |
| `confidence_levels` | list | `LOW`, `MEDIUM`, `HIGH` |
| `redact` | boolean | `true`, `false` |
| `output_format` | string | `text`, `json`, `sarif` |

Missing fields use defaults. Unknown fields are ignored. Invalid supported fields fail loudly.

Precedence:

```text
built-in defaults -> config file -> explicit CLI options
```

A config in the scan root takes priority over a config in the current working directory.

---

## Output Formats

### Text

Text is the default format and is intended for interactive terminal use.

```bash
python3 main.py test_dirs
```

### JSON

JSON emits a list of detailed findings and can include detected values or redacted display values.

```bash
python3 main.py test_dirs --format json
python3 main.py test_dirs --format json --redact
```

JSON mode emits only JSON, without scan headers or summaries.

### SARIF

SARIF emits one SARIF 2.1.0 JSON document for static-analysis integrations.

```bash
python3 main.py test_dirs --format sarif
python3 main.py test_dirs --format sarif > sentinelscan.sarif
```

The SARIF report contains one rule definition per unique rule ID and one result per finding. Result paths are relative to the scan root and use `/` separators so reports remain portable across operating systems.

Severity mapping:

| SentinelScan | SARIF |
|---|---|
| `LOW` | `note` |
| `MEDIUM` | `warning` |
| `HIGH` | `error` |

SARIF messages never include detected secret values. The `--redact` flag therefore does not change SARIF content.

---

## Filtering

Filters are applied before any output formatter runs. Text, JSON, and SARIF therefore receive the same filtered finding list.

```bash
python3 main.py test_dirs --format sarif --severity HIGH MEDIUM
python3 main.py test_dirs --format sarif --confidence HIGH
python3 main.py test_dirs --format sarif \
  --severity HIGH \
  --confidence HIGH
```

---

## Redaction

```bash
python3 main.py test_dirs --redact
python3 main.py test_dirs --format json --redact
```

Redaction happens only while rendering text or JSON. Detection and filtering still use the original value.

| Original | Redacted |
|---|---|
| `abcd` | `[REDACTED]` |
| `abcdef` | `a****f` |
| `abc1234567890j` | `ab***********0j` |

---

## Suppression

### File-level ignore

Create `.sentinelscanignore` in the scan root or a parent directory.

```gitignore
ignored_dir/
*.generated.py
```

### Inline ignore

Suppress all findings on a line:

```python
password = "abcdef"  # sentinelscan: ignore
```

Suppress specific rules only:

```python
api_key = "AKIAEXAMPLE123456789"  # sentinelscan: ignore API_KEY
```

---

## Common Commands

```bash
python3 -m pytest
python3 -m ruff check .
python3 main.py test_dirs
python3 main.py test_dirs --format json
python3 main.py test_dirs --format sarif
python3 main.py test_dirs --severity HIGH MEDIUM
python3 main.py test_dirs --confidence HIGH --redact
```
