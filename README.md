# SentinelScan

SentinelScan is a Python CLI static-analysis tool that scans Python codebases for hardcoded secrets.

It uses Python AST parsing to extract candidate values, applies a rule engine, and reports findings with file path, line number, rule ID, severity, confidence, reason, variable name, and value metadata.

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
- Supports human-readable text, machine-readable JSON, and SARIF 2.1.0 output
- Masks secret values by default, supports an explicit `--unsafe-show-secrets` opt-in, and provides exact severity/confidence filters
- Includes pytest coverage, pre-commit hooks, and GitHub Actions CI on Ubuntu and Windows

---

## Requirements

- Python 3.11+
- No third-party runtime dependencies
- Development tools from `requirements-dev.txt`

---

## Setup

```bash
git clone https://github.com/Saharsh1123/SentinelScan.git
cd SentinelScan
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements-dev.txt
```

---

## Quick Start

Scan a directory with text output:

```bash
python3 main.py ./your_directory
```

Generate JSON:

```bash
python3 main.py ./your_directory --format json
```

Generate SARIF 2.1.0:

```bash
python3 main.py ./your_directory --format sarif
```

Filter exact levels:

```bash
python3 main.py ./your_directory \
  --severity HIGH MEDIUM \
  --confidence HIGH
```

Text and JSON mask detected values by default. Plaintext output requires an explicit unsafe opt-in:

```bash
python3 main.py ./your_directory --unsafe-show-secrets
```

SARIF output never serializes detected secret values, even when `--unsafe-show-secrets` is provided.

---

## Config File

SentinelScan first checks the scan root for `sentinelscan.json`. If none exists there, it checks the current working directory.

```json
{
  "severity_levels": ["HIGH", "MEDIUM"],
  "confidence_levels": ["HIGH"],
  "output_format": "sarif"
}
```

Supported output formats are `text`, `json`, and `sarif`. Explicit CLI options override config values. Secret disclosure cannot be enabled from `sentinelscan.json`; it requires `--unsafe-show-secrets` on each invocation.

---

## Example Text Output

```text
Scanning 4 Python files...

--- Findings ---

[HIGH] test_dirs/test_repo/open_vulns.py:4 AWS Access Key -> AK****************89
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
    "value": "AK****************89",
    "reason": "value matched AKIA-prefixed AWS access key pattern",
    "entropy": 3.91,
    "confidence": "HIGH"
  }
]
```

JSON mode prints only JSON.

---

## SARIF Output

SARIF output is a single SARIF 2.1.0 JSON document. It contains:

- one analysis run produced by `SentinelScan`
- one rule definition per unique rule ID
- one result per finding
- SARIF levels mapped from SentinelScan severity:
  - `LOW` to `note`
  - `MEDIUM` to `warning`
  - `HIGH` to `error`
- file URIs relative to the scan root and normalized with `/`
- source line numbers
- descriptive messages without detected secret values

Redirect the report to a file for CI or later GitHub code-scanning integration:

```bash
python3 main.py ./your_directory --format sarif > sentinelscan.sarif
```

---

## Documentation

| Document | Purpose |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | CLI usage, safe secret display, config, output formats, filtering, suppression |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Pipeline, modules, models, SARIF serialization |
| [`docs/DETECTION_RULES.md`](docs/DETECTION_RULES.md) | Rules, supported syntax, limitations |
| [`docs/TESTING.md`](docs/TESTING.md) | Test layout, SARIF coverage, and CI strategy |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | Local setup, pre-commit, and development workflow |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Current capabilities and future improvements |

---

## Project Structure

```text
SentinelScan/
├── .github/workflows/
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
├── sarif.py
└── scanner.py
```

Generated files such as `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, virtual environments, SARIF reports, and ZIP archives should not be committed.

---

## Testing and Linting

```bash
python3 -m black --check .
python3 -m ruff check .
python3 -m pytest
```

Focused SARIF tests:

```bash
python3 -m pytest tests/test_output/test_sarif_output.py tests/test_cli/test_cli_sarif.py
```

Manual smoke tests:

```bash
python3 main.py test_dirs
python3 main.py test_dirs --format json
python3 main.py test_dirs --format sarif
```

---

## Current Limitations

- Only scans Python files
- Only evaluates supported hardcoded string-literal patterns
- Does not follow values across variables
- Does not scan `.env`, JSON, YAML, TOML, or generic text files
- Does not perform multi-file data-flow analysis or taint analysis
- SARIF V1 does not yet include fingerprints, remediation guidance, column ranges, or upload automation
- Can produce false positives or false negatives

---

## License

MIT License. See [`LICENSE`](LICENSE).
