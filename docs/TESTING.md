# Testing

SentinelScan uses unit tests and CLI integration tests to protect scanner and output behavior.

---

## Run Tests

```bash
python3 -m pytest
python3 -m pytest -q
```

Run specific areas:

```bash
python3 -m pytest tests/test_ast
python3 -m pytest tests/test_cli
python3 -m pytest tests/test_config
python3 -m pytest tests/test_output
```

Run only SARIF coverage:

```bash
python3 -m pytest tests/test_output/test_sarif_output.py tests/test_cli/test_cli_sarif.py
```

---

## Test Strategy

| Area | Purpose |
|---|---|
| AST tests | Candidate extraction and line numbers |
| Rule tests | Candidate-to-finding behavior |
| Confidence tests | Entropy and confidence scoring |
| Scanner tests | File scanning and inline-ignore integration |
| Config tests | Defaults, validation, lookup precedence, and supported formats |
| Output tests | Filtering, safe secret rendering, masking boundaries, and SARIF construction |
| CLI tests | Real command behavior through subprocesses |

Tests should cover one meaningful behavior at a time and avoid repeating behavior already proven at a lower layer.

---

## Test Layout

```text
tests/
├── test_ast/
├── test_cli/
│   └── test_cli_sarif.py
├── test_config/
├── test_output/
│   ├── test_sarif_output.py
│   └── test_secret_display.py
├── helpers.py
├── test_apply_rules.py
├── test_confidence.py
├── test_ignore.py
├── test_inline_ignore.py
└── test_scanner.py
```

---

## Secret-Display Coverage

The secret-display tests verify:

- text and JSON mask values by default
- `--unsafe-show-secrets` is the only CLI opt-in to plaintext output
- the removed `--redact` flag is rejected
- config files cannot enable plaintext secret display
- short, medium, and long masking branches remain deterministic
- JSON remains machine-readable when the unsafe flag is used
- SARIF remains secret-free regardless of the unsafe flag

---

## SARIF Coverage

The SARIF unit tests verify:

- stable rule metadata
- `LOW`/`MEDIUM`/`HIGH` to `note`/`warning`/`error` mapping
- repository-relative POSIX file URIs
- required SARIF 2.1.0 document structure
- one rule definition per unique rule ID
- one result per finding
- valid empty reports
- non-disclosure of detected secret values

The SARIF CLI tests verify:

- end-to-end CLI dispatch and JSON serialization
- relative paths through the real scan pipeline
- multiple findings and duplicate rule IDs
- severity and confidence filtering before serialization
- config and CLI format selection
- machine-readable empty output

The suite intentionally does not repeat every detector-rule case in SARIF tests. Detection rules and filtering are already tested independently; SARIF tests focus on serialization and integration boundaries.

---

## Important Coverage

- supported AST syntax shapes
- rule matching and multiple classifications
- config defaults, lookup, validation, and output formats
- exact severity/confidence list filters
- JSON output remains pure JSON
- SARIF output remains one pure JSON object
- text output includes readable finding details
- text and JSON mask values by default and expose plaintext only with `--unsafe-show-secrets`
- SARIF never serializes detected values, even with the unsafe plaintext flag
- `.sentinelscanignore` suppresses files
- inline ignores suppress only intended findings
- invalid CLI choices fail cleanly

---

## CI

GitHub Actions runs Black checks, Ruff, pytest, and a CLI smoke test on Ubuntu and Windows with Python 3.11 and 3.12.

Local equivalent:

```bash
python3 -m black --check .
python3 -m ruff check .
python3 -m pytest
```
