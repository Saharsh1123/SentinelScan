# Testing

SentinelScan uses unit tests and CLI integration tests to protect scanner behavior.

---

## Run Tests

```bash
pytest
python3 -m pytest
pytest -q
```

Run specific areas:

```bash
pytest tests/test_ast
pytest tests/test_cli
pytest tests/test_config
pytest tests/test_output
```

---

## Test Strategy

| Area | Purpose |
|---|---|
| AST tests | Candidate extraction and line numbers |
| Rule tests | Candidate-to-finding behavior |
| Confidence tests | Entropy and confidence scoring |
| Scanner tests | File scanning and inline ignore integration |
| Config tests | Defaults, validation, and partial config loading |
| Output tests | Filtering, JSON schema, text output, redaction |
| CLI tests | Real command behavior through subprocess |

Tests should be focused: one important behavior per test, no redundant assertions.

---

## Test Layout

```text
tests/
├── test_ast/
├── test_cli/
├── test_config/
├── test_output/
├── helpers.py
├── test_apply_rules.py
├── test_confidence.py
├── test_ignore.py
├── test_inline_ignore.py
└── test_scanner.py
```

---

## Important Coverage

- supported AST syntax shapes
- rule matching and multiple classifications
- config defaults and validation
- exact severity/confidence list filters
- JSON output remains pure JSON
- text output includes readable finding details
- redaction works in text and JSON
- `.sentinelscanignore` suppresses files
- inline ignores suppress only intended findings
- invalid CLI choices fail cleanly

---

## CI

GitHub Actions runs the test suite on push and pull request.

Local pre-commit check:

```bash
ruff check .
pytest
```
