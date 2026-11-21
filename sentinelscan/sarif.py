"""SARIF 2.1.0 serialization for SentinelScan findings.

The serializer converts already-filtered ``Finding`` objects into one SARIF
JSON document. Rule metadata is emitted once per unique rule ID, while every
finding remains a separate result. Detected secret values are intentionally
excluded from SARIF output.
"""

import json
from pathlib import Path

LEVELS = {"LOW": "note", "MEDIUM": "warning", "HIGH": "error"}


def build_rule_definition(filtered_finding):
    """Build the SARIF rule metadata associated with one finding.

    Args:
        filtered_finding (Finding): Finding whose stable rule metadata should
            be represented.

    Returns:
        dict: SARIF reporting descriptor for the finding's rule ID.
    """
    return {
        "id": filtered_finding.rule_id,
        "name": filtered_finding.rule_name,
        "shortDescription": {"text": filtered_finding.reason},
        "defaultConfiguration": {"level": LEVELS[filtered_finding.severity]},
    }


def build_sarif_result(filtered_finding, scan_root):
    """Build one SARIF result with a scan-root-relative source location.

    Args:
        filtered_finding (Finding): Finding to serialize.
        scan_root (str | Path): Root directory supplied to the scanner.

    Returns:
        dict: SARIF result object for the finding.
    """
    # SARIF artifact URIs should be portable and relative to the scanned root.
    relative_path = (
        Path(filtered_finding.file_path)
        .resolve()
        .relative_to(Path(scan_root).resolve())
        .as_posix()
    )

    return {
        "ruleId": filtered_finding.rule_id,
        "level": LEVELS[filtered_finding.severity],
        "message": {"text": filtered_finding.reason},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": relative_path},
                    "region": {"startLine": filtered_finding.line_number},
                }
            }
        ],
    }


def output_sarif(filtered_findings, path):
    """Print one machine-readable SARIF 2.1.0 document.

    Args:
        filtered_findings (list[Finding]): Findings after suppression and
            severity/confidence filtering.
        path (str | Path): Scan root used to create relative artifact URIs.

    Returns:
        None
    """
    # A dictionary keyed by rule ID prevents duplicate rule definitions while
    # preserving a separate result for every finding.
    unique_rules = {}
    results = []

    for filtered_finding in filtered_findings:
        unique_rules[filtered_finding.rule_id] = build_rule_definition(filtered_finding)
        results.append(build_sarif_result(filtered_finding, path))

    rules = list(unique_rules.values())

    # SARIF output is one top-level object, even when no findings are present.
    finding = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SentinelScan",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }

    print(json.dumps(finding, indent=2))
