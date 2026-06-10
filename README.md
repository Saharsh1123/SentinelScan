# SentinelScan

SentinelScan is a Python CLI static-analysis tool that scans Python codebases for hardcoded secrets.

It uses Python AST parsing to extract candidate values, applies a small rule engine, and reports findings with file path, line number, rule ID, severity, confidence, reason, variable name, and value.

> SentinelScan is a learning-focused project. It is not a replacement for mature tools such as GitHub secret scanning, Gitleaks, TruffleHog, Semgrep, or CodeQL.

---

## Features

- Recursively scans Python files under a target directory
- Supports `.sentinelscanignore` file-level suppression
- Supports generic and rule-specific inline ignores
- Extracts candidates from common Python syntax:
  - simple assignments
  - annotated assignments
  - attribute assignments
  - subscript assignments with string keys
  - dictionary literals with string key/value pairs
  - function keyword arguments with string values
  - multiple assignment targets
- Detects passwords, API keys, tokens, generic secrets, and AWS access keys
- Reports severity, confidence, entropy, rule metadata, and reason
- Supports text output, JSON output, redaction, filters, and config files
- Includes pytest coverage and GitHub Actions CI

---

## Requirements

- Python 3.11+
- `pytest` for tests
- `ruff` for linting/formatting
- No third-party runtime dependencies

---

## Setup

```bash
git clone https://github.com/Saharsh1123/SentinelScan.git
cd SentinelScan
python3 -m venv venv
source venv/bin/activate
python3 -m pip install pytest ruff
```

---

## Quick Start

Scan a directory:

```bash
python3 main.py ./your_directory
```

Scan the fixture directory:

```bash
python3 main.py test_dirs
```

JSON output:

```bash
python3 main.py test_dirs --json
```

Filter exact levels:

```bash
python3 main.py test_dirs --severity HIGH MEDIUM --confidence HIGH
```

Redact values:

```bash
python3 main.py test_dirs --redact
```

---

## Config File

SentinelScan can read `sentinelscan.json` from the scan root.

```json
{
  "severity_levels": ["HIGH", "MEDIUM"],
  "confidence_levels": ["HIGH"],
  "redact": true,
  "output_format": "json"
}
```

CLI options override config values when explicitly provided.

---

## Example Text Output

```text
Scanning 4 Python files...

--- Findings ---

[HIGH] test_dirs/test_repo/open_vulns.py:4 AWS Access Key → AKIAEXAMPLE123456789
       Confidence: HIGH
       Reason: value matched AKIA-prefixed AWS access key pattern

Total findings: 1
```

---

## Example JSON Output

```json
[
  {
    "line": 4,
    "var_name": "random_var",
    "file": "test_dirs/test_repo/open_vulns.py",
    "rule_id": "AWS_ACCESS_KEY",
    "rule": "AWS Access Key",
    "severity": "HIGH",
    "value": "AKIAEXAMPLE123456789",
    "reason": "value matched AKIA-prefixed AWS access key pattern",
    "entropy": 3.91,
    "confidence": "HIGH"
  }
]
```

JSON mode prints only valid JSON.

---

## Documentation

| Document | Purpose |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | CLI usage, config, output, filtering, redaction |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Pipeline, modules, models |
| [`docs/DETECTION_RULES.md`](docs/DETECTION_RULES.md) | Rules, supported syntax, limitations |
| [`docs/TESTING.md`](docs/TESTING.md) | Test layout and test strategy |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Local setup and workflow |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Future improvements |

---

## Project Structure

```text
SentinelScan/
├── config/
├── detectors/
├── docs/
├── test_dirs/
├── tests/
├── cli.py
├── ignore.py
├── inline_ignore.py
├── main.py
├── output.py
└── scanner.py
```

Generated files such as `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, `venv/`, and ZIP archives should not be committed.

---

## Testing and Linting

```bash
ruff check .
pytest
python3 main.py test_dirs
python3 main.py test_dirs --json --severity HIGH --confidence HIGH --redact
```

---

## Current Limitations

- Only scans Python files
- Only evaluates supported hardcoded string-literal patterns
- Does not follow values across variables
- Does not scan `.env`, JSON, YAML, TOML, or generic text files
- Does not perform multi-file data-flow analysis or taint analysis
- Can produce false positives or false negatives

---

## License

MIT License. See [`LICENSE`](LICENSE).
