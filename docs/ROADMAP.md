# Roadmap and Limitations

This document summarizes SentinelScan's current status, known limitations, and planned improvements.

---

## Current Status

SentinelScan is an educational static-analysis project focused on Python hardcoded-secret detection.

Current capabilities include:

- Python AST parsing
- Candidate extraction
- Modular rule evaluation
- Structured `Rule`, `Candidate`, and `Finding` dataclasses
- Simple assignment detection
- Attribute assignment detection
- Subscript assignment detection
- Entropy metadata
- Confidence scoring
- Human-readable CLI output
- JSON output
- Severity filtering
- Confidence filtering
- Secret redaction
- `.sentinelscanignore`
- Generic inline ignores
- Rule-specific inline ignores
- Pytest test coverage
- Ruff linting
- GitHub Actions CI

SentinelScan is not a replacement for mature tools such as GitHub secret scanning, Gitleaks, TruffleHog, Semgrep, or CodeQL.

---

## Current Limitations

SentinelScan is intentionally scoped.

Current limitations:

- Only scans Python files (`.py`)
- Only evaluates hardcoded string literal assignments
- Does not fully analyze dictionary literals
- Does not detect secrets passed directly into function calls
- Does not detect secrets returned from functions
- Does not detect secrets built through string concatenation
- Does not follow values across variables
- Does not analyze environment files such as `.env`
- Does not perform multi-file data-flow analysis
- Does not perform taint analysis
- Does not support SARIF output yet
- Does not support custom user-defined rules yet
- Does not support full config-file behavior yet
- Detection rules may still produce false positives or false negatives

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

1. Add JSON config support
2. Add rule disabling through config
3. Add dictionary literal extraction
4. Add function-call keyword argument detection
5. Add SARIF output
6. Add packaging support with a console script entry point

---

## Planned Improvements

Potential future improvements:

- JSON config file support
- Configurable default redaction
- Configurable severity and confidence filters
- Rule disabling by rule ID
- Custom user-defined rules
- Dictionary literal scanning
- Function-call argument scanning
- Annotated assignment support
- String concatenation handling
- Constant propagation
- Additional secret patterns:
  - JWTs
  - Private keys
  - GitHub tokens
  - Slack tokens
  - Google API keys
  - Database connection strings
  - Bearer tokens
- Additional file types:
  - `.env`
  - `.json`
  - `.yaml`
  - `.toml`
  - generic text files
- SARIF output
- Markdown or HTML reports
- Summary statistics
- Baseline/diff scan mode
- Pre-commit hook support
- GitHub repository scanning
- Benchmark fixtures for larger repositories

---

## Possible Future Output Formats

Current output formats:

- Human-readable text
- JSON

Potential future formats:

- SARIF
- Markdown report
- HTML report
- CSV
- Baseline/diff report

---

## Long-Term Direction

Long-term, SentinelScan could evolve into a broader static-analysis learning project with:

- Multi-file scanning
- Configurable detection rules
- Additional file type support
- Lightweight data-flow tracking
- Taint-analysis concepts
- CI/CD integration
- GitHub code scanning integration
- Security-report generation

The main goal is to keep improving the scanner while preserving a clean architecture, strong tests, and explainable limitations.