# Architecture

SentinelScan separates file handling, AST extraction, rule evaluation, suppression, filtering, config, and output serialization.

---

## Pipeline

```text
CLI args
-> path validation
-> config loading and merge
-> .sentinelscanignore filtering
-> file reading
-> AST candidate extraction
-> rule evaluation
-> inline ignore filtering
-> severity/confidence filtering
-> text, JSON, or SARIF output
```

All output formats consume the same filtered `Finding` objects. Output formatting does not affect detection or confidence scoring.

---

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `cli.py` | Parse user CLI options |
| `main.py` | Coordinate the application flow |
| `config/config.py` | Resolve, load, and validate `sentinelscan.json` |
| `config/config_model.py` | Define scanner config defaults and allowed values |
| `scanner.py` | Discover files, scan files, attach file paths |
| `ignore.py` | Apply `.sentinelscanignore` patterns |
| `inline_ignore.py` | Suppress findings using inline comments |
| `output.py` | Filter findings and dispatch text, JSON, or SARIF rendering |
| `sarif.py` | Convert findings into one SARIF 2.1.0 document |
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

The AST analyzer creates candidates. The rule engine creates findings. Output modules serialize findings without changing detection data; text and JSON mask values unless plaintext display was explicitly requested.

---

## Config Flow

`ScannerConfig` starts with defaults:

```text
severity_levels = LOW, MEDIUM, HIGH
confidence_levels = LOW, MEDIUM, HIGH
show_secrets = false (runtime-only safe default)
output_format = text
```

Config resolution:

```text
scan-root sentinelscan.json
    otherwise current-working-directory sentinelscan.json
    otherwise built-in defaults
```

Explicit CLI options override supported config fields only when provided. Plaintext secret display is not configurable and requires the runtime-only `--unsafe-show-secrets` flag.

---

## SARIF Serialization

SARIF output is one top-level object containing one analysis run.

```text
SARIF document
└── runs[0]
    ├── tool.driver
    │   ├── name = SentinelScan
    │   └── rules[]
    └── results[]
```

`rules` contains one definition per unique `rule_id`. `results` contains one entry per finding, including repeated findings from the same rule.

SentinelScan maps severity values as follows:

```text
LOW -> note
MEDIUM -> warning
HIGH -> error
```

Result file URIs are made relative to the scan root and normalized with `/`. SARIF descriptions use rule reasons and intentionally omit detected secret values.

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

`.sentinelscanignore` runs before files are scanned.

Inline ignores run after findings are created and can suppress all findings on a line or only specific rule IDs.
