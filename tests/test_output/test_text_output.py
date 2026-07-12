"""Unit tests for text rendering of findings and skipped-file diagnostics."""

from detectors.models import Finding, SkippedFile
from output import output


def make_finding(file_path):
    """Create one finding with the fields consumed by text output."""
    return Finding(
        file_path=str(file_path),
        line_number=1,
        var_name="password",
        value="abcdef",
        rule_id="PASSWORD",
        rule_name="Password",
        severity="HIGH",
        reason="test finding",
        entropy=2.5,
        confidence="LOW",
    )


def test_text_output_displays_skipped_file_when_no_findings(tmp_path, capsys):
    """Skipped-only scans should not hide recoverable scan diagnostics."""
    skipped_file = SkippedFile(
        path=str(tmp_path / "invalid.py"),
        reason="syntax_error",
        message="syntax error at 1: invalid syntax",
    )

    output([], [skipped_file], "text", False, [tmp_path / "invalid.py"], tmp_path)

    stdout = capsys.readouterr().out

    assert stdout.count("--- Skipped ---") == 1
    assert f"File: {skipped_file.path}" in stdout
    assert "Reason: syntax_error" in stdout
    assert "Details: syntax error at 1: invalid syntax" in stdout
    assert "No vulnerabilities found." in stdout
    assert "--- Findings ---" not in stdout


def test_text_output_displays_skipped_files_and_findings_together(tmp_path, capsys):
    """The two result channels should render as separate text sections."""
    vulnerable_file = tmp_path / "vulnerable.py"
    skipped_file = SkippedFile(
        path=str(tmp_path / "invalid.py"),
        reason="syntax_error",
        message="syntax error at 1: invalid syntax",
    )

    output(
        [make_finding(vulnerable_file)],
        [skipped_file],
        "text",
        False,
        [vulnerable_file, tmp_path / "invalid.py"],
        tmp_path,
    )

    stdout = capsys.readouterr().out

    assert stdout.count("--- Skipped ---") == 1
    assert stdout.count("--- Findings ---") == 1
    assert "Reason: syntax_error" in stdout
    assert f"[HIGH] {vulnerable_file}:1 Password" in stdout
    assert "Total findings: 1" in stdout
