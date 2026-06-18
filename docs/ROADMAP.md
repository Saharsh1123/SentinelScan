# Roadmap

SentinelScan is currently a Python-only static-analysis learning project focused on hardcoded secret detection.

---

## Current Strengths

- recursive Python file scanning
- AST-based candidate extraction
- built-in rule engine
- severity and confidence metadata
- config file support and CLI precedence
- text, JSON, and SARIF 2.1.0 output
- repository-relative SARIF locations
- redaction for text and JSON output
- file-level and inline ignores
- broad pytest coverage
- Ubuntu and Windows CI across Python 3.11 and 3.12

---

## Near-Term Improvements

- package with `pyproject.toml`
- console command entry point
- JSONL output
- configurable rule enable/disable support
- SARIF validation against the official schema in CI
- SARIF rule help text and remediation guidance
- stable SARIF fingerprints for alert tracking

---

## Later Improvements

- scan `.env`, JSON, YAML, TOML, and text files
- lightweight variable tracking
- taint-analysis concepts
- GitHub code-scanning upload workflow
- performance improvements for larger repos
- richer SARIF regions, columns, tags, and metadata

---

## Non-Goals for Now

- full inter-file data flow
- production-grade secret scanning
- dynamic/runtime analysis
- replacing established security tools
