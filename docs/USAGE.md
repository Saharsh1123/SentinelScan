# Usage

## Filter findings

`--severity` and `--confidence` accept one or more exact levels
(`LOW`, `MEDIUM`, `HIGH`). A finding must match both selections. Put the
path before these options.

```sh
sentinelscan ./src --severity HIGH MEDIUM --confidence HIGH
```

## Set defaults

SentinelScan reads `sentinelscan.json` from the scan root. If no config file
exists there, it looks in the current working directory. Missing fields use
the built-in defaults of text output and all severity and confidence levels.
Explicit CLI options override the config.

```json
{
  "severity_levels": ["HIGH", "MEDIUM"],
  "confidence_levels": ["HIGH"],
  "output_format": "json"
}
```

Unknown fields and invalid values are rejected.

## Read reports

JSON prints an array of findings. SARIF prints a single 2.1.0 document with
paths relative to the scan root. SARIF maps `LOW` to `note`, `MEDIUM` to
`warning`, and `HIGH` to `error`.

Text reports list file read, encoding, and syntax failures under **Skipped**
with reason codes `io_error`, `encoding_error`, and `syntax_error`.

Masking in text and JSON fully hides values up to four characters and leaves
a short prefix and suffix on longer values. To see plaintext in text or JSON,
pass `--unsafe-show-secrets` for that run. Keep plaintext reports private.
The config file cannot enable plaintext output, and the flag has no effect on
SARIF.

## Suppress findings

Put a `.sentinelscanignore` file in the scan root or a parent directory.
SentinelScan uses the nearest file, matches globs against file names and
paths relative to the ignore file, and treats a trailing `/` as a directory
pattern.

```gitignore
generated/
*.generated.py
```

To suppress findings on one line, add `# sentinelscan: ignore`. List rule
IDs after `ignore` to suppress only those rules.

```python
api_key = "example-key"  # sentinelscan: ignore API_KEY
```
