# SentinelScan

SentinelScan scans directories for possible hardcoded secrets in Python files. It
looks for string literals in supported Python syntax and matches them against
a small set of name and value patterns.

SentinelScan v0.1.0 is an experimental learning project. Active development has
ended. Use an established secret scanner for production security enforcement.

## Install

SentinelScan requires Python 3.11 or later and has no third-party runtime
dependencies. Download the wheel from [GitHub Releases](https://github.com/Saharsh1123/SentinelScan/releases)
and install it in an active virtual environment.

```sh
python -m pip install ./sentinelscan-0.1.0-py3-none-any.whl
```

From a source checkout, you can also install with `python -m pip install .`
or run it directly with `python main.py`.

## Run a scan

```sh
sentinelscan --help
sentinelscan ./src
sentinelscan ./src --format json
sentinelscan ./src --format sarif > sentinelscan.sarif
```

By default, text output shows the file, line, matched rule, severity, and
confidence for each finding. Text and JSON mask detected values by default.
SARIF omits detected values.

| Exit code | Meaning |
| --- | --- |
| `0` | No findings remain after filtering. |
| `1` | One or more findings remain after filtering. |
| `2` | Invalid arguments, an invalid scan path, or a reported configuration error. |
| `3` | An internal error stopped the scan. |

## Limitations

SentinelScan scans `.py` files and only checks supported string-literal
patterns. It cannot trace values through variables or detect secrets assembled
at runtime. False positives and false negatives are possible.

Ignore patterns can exclude files. The scan can also skip files it cannot
read, decode, or parse. Those diagnostics appear only in text output. JSON
and SARIF omit them. Exit code `0` does not guarantee complete coverage.

See the [usage guide](docs/USAGE.md) for filtering, configuration, and ignores,
and [detection rules](docs/DETECTION_RULES.md) for the supported syntax and
match patterns.

[MIT License](LICENSE)
