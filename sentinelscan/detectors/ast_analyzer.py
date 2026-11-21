"""
AST-based candidate extraction for SentinelScan.

This module translates supported Python syntax into `Candidate` objects while
preserving source variable and key spelling. It does not decide whether a
candidate is a vulnerability; that is the rule engine's job.
"""

import ast
import textwrap

from sentinelscan.detectors.models import Candidate, SkippedFile


def parse_ast(source_code):
    """
    Parse Python source code or describe why parsing was skipped.

    Dedenting keeps multiline test strings parseable without affecting normal
    files. The parser records syntax details but does not know the source path;
    the scanner attaches that path later.

    Args:
        source_code (str): Raw Python source code.

    Returns:
        tuple[ast.Module | None, SkippedFile | None]: Parsed syntax tree on
            success, or a structured syntax-error diagnostic on failure.
    """
    source_code = textwrap.dedent(source_code)

    try:
        return ast.parse(source_code), None
    except SyntaxError as error:
        return None, SkippedFile(
            reason="syntax_error",
            message=f"syntax error at {error.lineno}: {error.msg}",
        )


def get_assignments(tree):
    """
    Yield supported assignment nodes from a parsed AST.

    Supports normal assignments and annotated assignments.

    Args:
        tree (ast.AST): Parsed syntax tree.

    Yields:
        ast.Assign | ast.AnnAssign: Supported assignment nodes.
    """
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            yield node


def get_function_calls(tree):
    """
    Yield function call nodes from a parsed AST.

    This includes standalone calls and calls used inside larger expressions.

    Args:
        tree (ast.AST): Parsed syntax tree.

    Yields:
        ast.Call: Function call nodes found during traversal.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def extract_candidates_from_dict(dict_node):
    """
    Yield candidates from string key/value pairs in a dictionary literal.

    Example:
        config = {"password": "abcdef"}

    Produces:
        Candidate(var_name="password", value="abcdef", line_number=...)

    Args:
        dict_node (ast.Dict): Dictionary literal node.

    Yields:
        Candidate: Candidate generated from a string dictionary key/value pair.
    """
    for key_node, value_node in zip(dict_node.keys, dict_node.values):
        if key_node is None:
            continue

        if not (
            isinstance(key_node, ast.Constant)
            and isinstance(key_node.value, str)
            and isinstance(value_node, ast.Constant)
            and isinstance(value_node.value, str)
        ):
            continue

        yield Candidate(
            line_number=getattr(value_node, "lineno", getattr(dict_node, "lineno", 0)),
            var_name=key_node.value,
            value=value_node.value,
        )


def extract_candidates_from_function_call(call_node):
    """
    Yield candidates from string keyword arguments in a function call.

    Example:
        connect(password="abcdef")

    Produces:
        Candidate(var_name="password", value="abcdef", line_number=...)

    Positional arguments and **kwargs are ignored because they do not provide a
    clear secret-related name for the rule engine.

    Args:
        call_node (ast.Call): Function call node.

    Yields:
        Candidate: Candidate generated from a string keyword argument.
    """
    for keyword in call_node.keywords:
        if keyword.arg is None:
            continue

        if not (
            isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        ):
            continue

        yield Candidate(
            line_number=getattr(
                keyword.value, "lineno", getattr(call_node, "lineno", 0)
            ),
            var_name=keyword.arg,
            value=keyword.value.value,
        )


def extract_node_value(node):
    """
    Extract a string literal from an assignment node.

    Non-string assignments are ignored because the current detector only
    evaluates hardcoded string values.

    Args:
        node (ast.Assign | ast.AnnAssign): Assignment node.

    Returns:
        str | None: Extracted string value, or None if unsupported.
    """
    val = node.value

    if not (isinstance(val, ast.Constant) and isinstance(val.value, str)):
        return None

    return val.value


def extract_target_nodes(node):
    """
    Yield target nodes from normal or annotated assignments.

    Normal assignments may have multiple targets:
        a = b = "secret"

    Annotated assignments have one target:
        password: str = "secret"

    Args:
        node (ast.Assign | ast.AnnAssign): Assignment node.

    Yields:
        ast.AST: Assignment target nodes.
    """
    if isinstance(node, ast.AnnAssign):
        yield node.target

    elif isinstance(node, ast.Assign):
        for target in node.targets:
            yield target


def extract_variable_path_from_target(target):
    """
    Extract source-preserving variable paths from assignment targets.

    Supports simple variables, nested attributes, and string subscript keys:
        password = "secret"
        self.config.password = "secret"
        config["password"] = "secret"

    Args:
        target (ast.AST): Assignment target node.

    Yields:
        list[str]: Variable path components with their original spelling.
    """
    full_path = []
    temp_node = target

    if isinstance(temp_node, ast.Attribute):
        while isinstance(temp_node, ast.Attribute):
            full_path.append(temp_node.attr)
            temp_node = temp_node.value

        if not isinstance(temp_node, ast.Name):
            return

        full_path.append(temp_node.id)
        full_path.reverse()

    elif isinstance(target, ast.Name):
        full_path.append(target.id)

    elif isinstance(target, ast.Subscript):
        key = target.slice

        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            return

        full_path.append(key.value)

    if full_path:
        yield full_path


def extract_assignment_candidates(node, value):
    """
    Yield candidates from a string assignment node.

    Args:
        node (ast.Assign | ast.AnnAssign): Assignment node.
        value (str): Extracted string value assigned to the target.

    Yields:
        Candidate: Candidate generated from the assignment target and value.
    """
    for target in extract_target_nodes(node):
        for full_path in extract_variable_path_from_target(target):
            yield Candidate(
                line_number=node.lineno,
                var_name=full_path[-1],
                value=value,
            )


def extract_candidates(tree):
    """
    Yield candidate secret values from a successfully parsed syntax tree.

    Supports:
    - normal string assignments
    - annotated string assignments
    - string subscript assignments
    - dictionary literals with string key/value pairs
    - function calls with string keyword arguments

    Unsupported AST shapes are ignored. Syntax failures are handled by
    `parse_ast()` before this generator is called.

    Args:
        tree (ast.AST): Parsed Python syntax tree.

    Yields:
        Candidate: Extracted variable name, value, and line number.
    """
    for node in get_assignments(tree):
        if isinstance(node.value, ast.Dict):
            yield from extract_candidates_from_dict(node.value)
            continue

        value = extract_node_value(node)
        if value is None:
            continue

        yield from extract_assignment_candidates(node, value)

    for call_node in get_function_calls(tree):
        yield from extract_candidates_from_function_call(call_node)
