# Roadmap and Limitations

This document lists SentinelScan's current limitations and possible future improvements.

---

## Current Project Status

SentinelScan is an educational static-analysis project.

It currently demonstrates:

- Python AST parsing
- Candidate extraction
- Modular rule evaluation
- Structured `Rule`, `Candidate`, and `Finding` models
- Human-readable CLI output
- JSON output
- Severity filtering
- Secret redaction
- Pytest-based test coverage
- Ruff linting
- GitHub Actions CI

It is not a replacement for mature secret-scanning tools such as GitHub secret scanning, Gitleaks, TruffleHog, Semgrep, or CodeQL.

---

## Current Limitations

- Only scans Python files (`.py`)
- Only analyzes assignment statements supported by the current AST logic
- Does not currently support dictionary/subscript assignments such as `config["password"] = "value"`
- Does not currently detect secrets passed directly into function calls
- Does not currently detect secrets returned from functions
- Does not currently detect secrets built through string concatenation
- Does not currently detect secrets loaded from environment variables
- Does not perform entropy scoring yet
- Does not currently assign confidence levels
- Does not perform deep data-flow analysis
- Does not perform taint analysis
- Does not support SARIF output yet
- Does not currently support custom user-defined rules
- Detection rules may still produce false positives or false negatives
- Redaction is optional, so users should use `--redact` when sharing scan output

---

## Planned Improvements

Potential future improvements:

- Add entropy-based scoring for random-looking secrets
- Add confidence scoring
- Add support for dictionary/subscript assignments
- Add support for annotated assignments
- Add support for function-call argument detection
- Add support for string concatenation detection
- Add config file support
- Add ignore rules for files, directories, or specific findings
- Add SARIF output for GitHub code scanning integration
- Add broader secret patterns such as JWTs and private keys
- Add support for additional file types beyond Python
- Add benchmarking fixtures for larger repositories
- Add summarized scan statistics
- Add GitHub repository scanning
- Add HTML report generation
- Add baseline/diff scan mode
- Add pre-commit hook support

---

## Near-Term Priorities

Recommended next improvements:

1. Add entropy scoring for high-randomness values
2. Add confidence levels separate from severity
3. Add support for dictionary/subscript assignments
4. Add config/ignore support
5. Add SARIF output for GitHub code scanning

---

## Severity vs Confidence

Future versions may separate severity and confidence.

```text
Severity = impact if the finding is real
Confidence = likelihood that the finding is real
```

Example:

```text
HIGH severity, HIGH confidence
HIGH severity, LOW confidence
MEDIUM severity, HIGH confidence
```

This would make reports more useful and reduce noisy output.

---

## Possible Future Output Formats

Current output formats:

- Human-readable text
- JSON

Potential future formats:

- SARIF
- HTML report
- Markdown report
- CSV
- Baseline/diff report

---

## Long-Term Direction

Long-term, SentinelScan could evolve into a broader static-analysis learning project with:

- Multi-file scanning
- Configurable rules
- Ignore comments
- More AST node support
- Lightweight data-flow tracking
- Taint-analysis concepts
- CI/CD integration
- GitHub repository scanning
- Security-report generation
