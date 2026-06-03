# Roadmap and Limitations

This document summarizes SentinelScan's current status, known limitations, and planned improvements.

---

## Current Status

SentinelScan is an educational static-analysis project focused on Python hardcoded-secret detection.

Current capabilities include:

- Python AST parsing
- candidate extraction
- modular rule evaluation
- structured `Rule`, `Candidate`, and `Finding` dataclasses
- simple assignment detection
- annotated assignment detection
- attribute assignment detection
- subscript assignment detection
- dictionary literal detection
- entropy metadata
- confidence scoring
- human-readable CLI output
- JSON output
- severity filtering
- confidence filtering
- secret redaction
- `.sentinelscanignore`
- generic inline ignores
- rule-specific inline ignores
- pytest test coverage
- Ruff linting
- GitHub Actions CI

SentinelScan is not a replacement for mature tools such as GitHub secret scanning, Gitleaks, TruffleHog, Semgrep, or CodeQL.

---

## Current Limitations

SentinelScan is intentionally scoped.

Current limitations:

- only scans Python files (`.py`)
- only evaluates supported hardcoded string-literal syntax
- does not detect secrets passed directly into function calls yet
- does not detect secrets returned from functions yet
- does not detect secrets built through string concatenation yet
- does not follow values across variables yet
- does not analyze environment files such as `.env`
- does not perform multi-file data-flow analysis
- does not perform taint analysis
- does not support SARIF output yet
- does not support custom user-defined rules yet
- does not support full config-file behavior yet
- detection rules may still produce false positives or false negatives

---

## Severity vs Confidence

SentinelScan separates severity from confidence.

```text
Severity   = impact if the finding is real
Confidence = likelihood that the finding is real
```

Examples:

```text
HIGH severity, HIGH confidence
HIGH severity, LOW confidence
MEDIUM severity, HIGH confidence
```

This makes output more useful because a finding can be dangerous but still low-confidence.

---

## Near-Term Priorities

Recommended next improvements:

1. Add function-call keyword argument detection
2. Add JSON config support
3. Add rule disabling through config
4. Add SARIF output
5. Add packaging support with a console script entry point
6. Add GitHub repository scanning through clone-and-scan workflow

---

## Planned Improvements

Potential future improvements:

- JSON config file support
- configurable default redaction
- configurable severity and confidence filters
- rule disabling by rule ID
- custom user-defined rules
- function-call argument scanning
- return statement scanning
- string concatenation handling
- constant propagation
- lightweight data-flow tracking
- taint-lite source-to-sink checks
- additional secret patterns:
  - JWTs
  - private keys
  - GitHub tokens
  - Slack tokens
  - Google API keys
  - database connection strings
  - bearer tokens
- additional file types:
  - `.env`
  - `.json`
  - `.yaml`
  - `.toml`
  - generic text files
- SARIF output
- Markdown or HTML reports
- summary statistics
- baseline/diff scan mode
- pre-commit hook support
- GitHub repository scanning
- benchmark fixtures for larger repositories

---

## Possible Future Output Formats

Current output formats:

- human-readable text
- JSON

Potential future formats:

- SARIF
- Markdown report
- HTML report
- CSV
- baseline/diff report

---

## Long-Term Direction

Long-term, SentinelScan could evolve into a broader static-analysis learning project with:

- multi-file scanning
- configurable detection rules
- additional file type support
- lightweight data-flow tracking
- taint-analysis concepts
- CI/CD integration
- GitHub code scanning integration
- security-report generation

The main goal is to keep improving the scanner while preserving a clean architecture, strong tests, and explainable limitations.
