"""Unit tests for AST parsing and structured syntax failures."""

import ast

from sentinelscan.detectors.ast_analyzer import parse_ast


def test_parse_ast_returns_tree_for_valid_source():
    tree, skipped_file = parse_ast('password = "abcdef"')

    assert isinstance(tree, ast.Module)
    assert skipped_file is None


def test_parse_ast_returns_structured_skip_for_invalid_syntax():
    tree, skipped_file = parse_ast('password = "abc')

    assert tree is None
    assert skipped_file is not None
    assert skipped_file.path is None
    assert skipped_file.reason == "syntax_error"
    assert skipped_file.message.startswith("syntax error at 1:")
    assert "unterminated string literal" in skipped_file.message
