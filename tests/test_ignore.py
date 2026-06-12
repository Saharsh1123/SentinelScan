from ignore import (
    filter_ignored_files,
    find_ignore_file,
    load_ignore_patterns,
    should_ignore,
)


def write_ignore_file(root_path, content):
    ignore_file = root_path / ".sentinelscanignore"
    ignore_file.write_text(content, encoding="utf-8")
    return ignore_file


# Return no ignore file when none exists
def test_find_ignore_file_returns_none_when_missing(tmp_path):
    ignore_file, ignore_root = find_ignore_file(tmp_path)

    assert ignore_file is None
    assert ignore_root is None


# Find ignore file in the scan root
def test_find_ignore_file_in_scan_root(tmp_path):
    expected_ignore_file = write_ignore_file(tmp_path, "ignored.py\n")

    ignore_file, ignore_root = find_ignore_file(tmp_path)

    assert ignore_file == expected_ignore_file
    assert ignore_root == tmp_path.resolve()


# Find ignore file in a parent directory
def test_find_ignore_file_in_parent_directory(tmp_path):
    write_ignore_file(tmp_path, "nested/\n")

    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()

    ignore_file, ignore_root = find_ignore_file(nested_dir)

    assert ignore_file == (tmp_path / ".sentinelscanignore")
    assert ignore_root == tmp_path.resolve()


# Missing ignore file should return empty patterns and no ignore root
def test_load_ignore_patterns_missing_file(tmp_path):
    patterns, ignore_root = load_ignore_patterns(tmp_path)

    assert patterns == []
    assert ignore_root is None


# Load patterns while skipping blank lines and comments
def test_load_ignore_patterns_skips_blank_lines_and_comments(tmp_path):
    write_ignore_file(
        tmp_path,
        """
        # comment
        venv/

        __pycache__/
        *.min.py
        """,
    )

    patterns, ignore_root = load_ignore_patterns(tmp_path)

    assert patterns == ["venv/", "__pycache__/", "*.min.py"]
    assert ignore_root == tmp_path.resolve()


# Directory patterns should ignore files inside that directory
def test_should_ignore_directory_pattern(tmp_path):
    write_ignore_file(tmp_path, "venv/\n")
    patterns, ignore_root = load_ignore_patterns(tmp_path)

    file_path = tmp_path / "venv" / "lib" / "file.py"
    file_path.parent.mkdir(parents=True)
    file_path.write_text("print('ignored')\n", encoding="utf-8")

    assert should_ignore(file_path, ignore_root, patterns) is True


# Nested directory patterns should ignore files inside that nested path
def test_should_ignore_nested_directory_pattern(tmp_path):
    write_ignore_file(tmp_path, "tests/fixtures/\n")
    patterns, ignore_root = load_ignore_patterns(tmp_path)

    file_path = tmp_path / "tests" / "fixtures" / "vulnerable.py"
    file_path.parent.mkdir(parents=True)
    file_path.write_text('password = "abcdef"\n', encoding="utf-8")

    assert should_ignore(file_path, ignore_root, patterns) is True


# Filename patterns should ignore matching filenames anywhere under the root
def test_should_ignore_filename_pattern(tmp_path):
    write_ignore_file(tmp_path, "secrets.py\n")
    patterns, ignore_root = load_ignore_patterns(tmp_path)

    file_path = tmp_path / "src" / "secrets.py"
    file_path.parent.mkdir()
    file_path.write_text('password = "abcdef"\n', encoding="utf-8")

    assert should_ignore(file_path, ignore_root, patterns) is True


# Glob patterns should ignore matching files
def test_should_ignore_glob_pattern(tmp_path):
    write_ignore_file(tmp_path, "*.min.py\n")
    patterns, ignore_root = load_ignore_patterns(tmp_path)

    file_path = tmp_path / "src" / "bundle.min.py"
    file_path.parent.mkdir()
    file_path.write_text('password = "abcdef"\n', encoding="utf-8")

    assert should_ignore(file_path, ignore_root, patterns) is True


# Non-matching files should not be ignored
def test_should_ignore_returns_false_for_non_matching_file(tmp_path):
    write_ignore_file(tmp_path, "ignored.py\n")
    patterns, ignore_root = load_ignore_patterns(tmp_path)

    file_path = tmp_path / "safe.py"
    file_path.write_text("username = 'safe'\n", encoding="utf-8")

    assert should_ignore(file_path, ignore_root, patterns) is False


# No patterns should never ignore files
def test_should_ignore_returns_false_without_patterns(tmp_path):
    file_path = tmp_path / "anything.py"
    file_path.write_text('password = "abcdef"\n', encoding="utf-8")

    assert should_ignore(file_path, tmp_path, []) is False


# Filter ignored files from a discovered file list
def test_filter_ignored_files_removes_ignored_files(tmp_path):
    write_ignore_file(tmp_path, "ignored.py\n")

    ignored_file = tmp_path / "ignored.py"
    kept_file = tmp_path / "kept.py"

    ignored_file.write_text('password = "abcdef"\n', encoding="utf-8")
    kept_file.write_text("username = 'safe'\n", encoding="utf-8")

    patterns, ignore_root = load_ignore_patterns(tmp_path)

    result = filter_ignored_files(
        [ignored_file, kept_file],
        ignore_root,
        patterns,
    )

    assert result == [kept_file]


# Directory ignores should work through filter_ignored_files
def test_filter_ignored_files_removes_files_inside_ignored_directory(tmp_path):
    write_ignore_file(tmp_path, "ignored_dir/\n")

    ignored_file = tmp_path / "ignored_dir" / "vulnerable.py"
    kept_file = tmp_path / "src" / "safe.py"

    ignored_file.parent.mkdir()
    kept_file.parent.mkdir()

    ignored_file.write_text('password = "abcdef"\n', encoding="utf-8")
    kept_file.write_text("username = 'safe'\n", encoding="utf-8")

    patterns, ignore_root = load_ignore_patterns(tmp_path)

    result = filter_ignored_files(
        [ignored_file, kept_file],
        ignore_root,
        patterns,
    )

    assert result == [kept_file]


# Parent ignore files should match paths relative to the ignore file root
def test_parent_ignore_file_matches_relative_to_parent_root(tmp_path):
    write_ignore_file(tmp_path, "project/ignored.py\n")

    project_dir = tmp_path / "project"
    project_dir.mkdir()

    ignored_file = project_dir / "ignored.py"
    ignored_file.write_text('password = "abcdef"\n', encoding="utf-8")

    patterns, ignore_root = load_ignore_patterns(project_dir)

    assert should_ignore(ignored_file, ignore_root, patterns) is True
