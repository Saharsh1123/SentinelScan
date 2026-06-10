# Usage Guide

This guide covers SentinelScan's CLI options, config file, output formats, filtering, redaction, and suppression.

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
| `--format text/json` | Select output format |
| `--severity LOW MEDIUM HIGH` | Keep exact severity levels |
| `--confidence LOW MEDIUM HIGH` | Keep exact confidence levels |
| `--redact` | Mask detected values |

Severity and confidence values are exact selections, not thresholds.

Examples:

```bash
python3 main.py test_dirs --severity HIGH
python3 main.py test_dirs --severity HIGH MEDIUM
python3 main.py test_dirs --confidence HIGH LOW
```

---

## Config File

Place `sentinelscan.json` in the scan root to set defaults for that project.

```json
{
  "severity_levels": ["HIGH", "MEDIUM"],
  "confidence_levels": ["HIGH"],
  "redact": true,
  "output_format": "json"
}
```

Supported fields:

| Field | Type | Allowed values |
|---|---|---|
| `severity_levels` | list | `LOW`, `MEDIUM`, `HIGH` |
| `confidence_levels` | list | `LOW`, `MEDIUM`, `HIGH` |
| `redact` | boolean | `true`, `false` |
| `output_format` | string | `text`, `json` |

Missing fields use defaults. Unknown fields are ignored. Invalid supported fields fail loudly.

Precedence:

```text
built-in defaults → sentinelscan.json → explicit CLI options
```

---

## Output Formats

Text output is the default:

```bash
python3 main.py test_dirs
```

JSON output:

```bash
python3 main.py test_dirs --format json
```

JSON mode emits only valid JSON so it can be parsed by scripts or CI jobs.

---

## Redaction

```bash
python3 main.py test_dirs --redact
python3 main.py test_dirs --format json --redact
```

Redaction happens only when rendering output. Detection still uses the original value.

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
pytest
ruff check .
python3 main.py test_dirs
python3 main.py test_dirs --format json
python3 main.py test_dirs --severity HIGH MEDIUM
python3 main.py test_dirs --confidence HIGH --redact
```
