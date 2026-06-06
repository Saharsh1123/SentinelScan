# Architecture

SentinelScan separates file handling, AST extraction, rule evaluation, suppression, filtering, config, and output formatting.

---

## Pipeline

```text
CLI args
→ path validation
→ config loading and merge
→ .sentinelscanignore filtering
→ file reading
→ AST candidate extraction
→ rule evaluation
→ inline ignore filtering
→ severity/confidence filtering
→ text or JSON output
```

---

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `cli.py` | Parse user CLI options |
| `main.py` | Coordinate the application flow |
| `config/config.py` | Load and validate `sentinelscan.json` |
| `config/config_model.py` | Define scanner config defaults and allowed values |
| `scanner.py` | Discover files, scan files, attach file paths |
| `ignore.py` | Apply `.sentinelscanignore` patterns |
| `inline_ignore.py` | Suppress findings using inline comments |
| `output.py` | Filter, redact, and render findings |
| `detectors/ast_analyzer.py` | Extract `Candidate` objects from supported AST shapes |
| `detectors/rule_engine.py` | Convert matching candidates into findings |
| `detectors/rules.py` | Define built-in rules |
| `detectors/confidence.py` | Calculate entropy and confidence |
| `detectors/models.py` | Define `Rule`, `Candidate`, and `Finding` |

---

## Data Models

`Candidate` is extracted source data that might be suspicious.

```text
line_number
var_name
value
```

`Finding` is a confirmed rule match.

```text
file_path
line_number
var_name
value
rule_id
rule_name
severity
reason
entropy
confidence
```

The AST analyzer creates candidates. The rule engine creates findings.

---

## Config Flow

`ScannerConfig` starts with safe defaults:

```text
severity_levels = LOW, MEDIUM, HIGH
confidence_levels = LOW, MEDIUM, HIGH
redact = false
output_format = text
```

Then SentinelScan applies:

```text
built-in defaults → scan-root sentinelscan.json → explicit CLI options
```

CLI options win only when explicitly provided.

---

## Supported AST Candidate Sources

- normal assignments
- annotated assignments
- attribute assignments
- string-key subscript assignments
- dictionary literals with string key/value pairs
- function keyword arguments with string values
- multiple assignment targets

Unsupported syntax is ignored instead of crashing the scan.

---

## Suppression

`.sentinelscanignore` runs before scanning files.

Inline ignores run after findings are created and can suppress all findings on a line or only specific rule IDs.
