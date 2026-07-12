# Architecture

SentinelScan separates file handling, AST extraction, rule evaluation, suppression, filtering, config, and output serialization.

---

## Pipeline

```text
CLI args
-> path validation
-> config loading and merge
-> .sentinelscanignore filtering
-> Python-aware source decoding
-> structured read failure or source text
-> AST parse
-> structured syntax failure or syntax tree
-> candidate extraction
-> rule evaluation
-> inline ignore filtering
-> aggregate findings + skipped-file diagnostics
-> severity/confidence filtering
-> text, JSON, or SARIF output
```

All output formats consume the same filtered `Finding` objects. Text output also renders `SkippedFile` diagnostics; JSON and SARIF currently serialize findings only. Output formatting does not affect detection or confidence scoring.

---

## Module Responsibilities

| Module | Responsibility |
|---|---|
| `cli.py` | Parse user CLI options |
| `main.py` | Coordinate the application flow |
| `config/config.py` | Resolve, load, and validate `sentinelscan.json` |
| `config/config_model.py` | Define scanner config defaults and allowed values |
| `scanner.py` | Discover and decode files, attach paths, and aggregate findings separately from skipped-file diagnostics |
| `ignore.py` | Apply `.sentinelscanignore` patterns |
| `inline_ignore.py` | Suppress findings using inline comments |
| `output.py` | Filter findings and dispatch text, JSON, or SARIF rendering |
| `sarif.py` | Convert findings into one SARIF 2.1.0 document |
| `detectors/ast_analyzer.py` | Extract source-preserving `Candidate` objects from supported AST shapes |
| `detectors/rule_engine.py` | Apply rules and conservative name-context checks |
| `detectors/rules.py` | Define built-in rules |
| `detectors/confidence.py` | Calculate entropy and confidence |
| `detectors/models.py` | Define `Rule`, `Candidate`, `Finding`, and `SkippedFile` |

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

`SkippedFile` records a recoverable analysis limitation. It contains a file path when the scanner knows it, a stable reason category, and a human-readable detail message. It never represents a vulnerability.

The parser owns syntax-failure reason and message data. The scanner owns source decoding, file-read failures, path enrichment, and aggregation. The output layer owns rendering. This keeps the two result channels separate:

```text
Finding     = analyzed code matched a security rule
SkippedFile = a file could not be analyzed safely
```

The AST analyzer creates candidates and preserves source identifier spelling. The rule engine creates findings, suppresses only explicit absence context for name-based matches, and leaves structured value-pattern matches unaffected. Output modules serialize findings without changing detection data; text and JSON mask values unless plaintext display was explicitly requested.

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

Unsupported but valid AST shapes are ignored. Invalid Python syntax becomes a structured `SkippedFile` diagnostic so the repository scan can continue.

---

## Suppression

`.sentinelscanignore` runs before files are scanned.

Inline ignores run after findings are created and can suppress all findings on a line or only specific rule IDs.
