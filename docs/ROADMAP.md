# Roadmap

SentinelScan is currently a Python-only static-analysis learning project focused on hardcoded secret detection.

---

## Current Strengths

- recursive Python file scanning
- AST-based candidate extraction
- built-in rule engine
- severity and confidence metadata
- config file support
- JSON and text output
- redaction
- file-level and inline ignores
- broad pytest coverage

---

## Near-Term Improvements

- package with `pyproject.toml`
- console command entry point
- SARIF output
- JSONL output
- configurable rule enable/disable support
- better docs examples

---

## Later Improvements

- scan `.env`, JSON, YAML, TOML, and text files
- lightweight variable tracking
- taint-analysis concepts
- GitHub repository scanning workflow
- performance improvements for larger repos
- GitHub code scanning integration

---

## Non-Goals for Now

- full inter-file data flow
- production-grade secret scanning
- dynamic/runtime analysis
- replacing established security tools
