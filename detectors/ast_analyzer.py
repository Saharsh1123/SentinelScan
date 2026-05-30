import ast
import textwrap

from detectors.models import Candidate


def parse_ast(file):
    """
    Parse Python source code into an AST.

    Dedents source first so indented multiline test strings can be parsed
    consistently.

    Args:
        file (str): Raw Python source code.

    Returns:
        ast.AST | None: Parsed AST object, or None if parsing fails.
    """
    file = textwrap.dedent(file)

    try:
        return ast.parse(file)
    except SyntaxError:
        return None


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


def extract_candidates_from_dict(dict_node):
    """
    Yield candidates from string key/value pairs in a dictionary literal.

    Example:
        {"password": "abcdef"}

    Produces:
        Candidate(var_name="password", value="abcdef", line_number=...)
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
            var_name=key_node.value.lower(),
            value=value_node.value,
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
    Extract normalized variable paths from assignment targets.

    Supports simple variables, nested attributes, and string subscript keys:
        password = "secret"
        self.config.password = "secret"
        config["password"] = "secret"

    Args:
        target (ast.AST): Assignment target node.

    Yields:
        list[str]: Lowercased variable path components.
    """
    full_path = []
    temp_node = target

    if isinstance(temp_node, ast.Attribute):
        while isinstance(temp_node, ast.Attribute):
            full_path.append(temp_node.attr.lower())
            temp_node = temp_node.value

        if not isinstance(temp_node, ast.Name):
            return

        full_path.append(temp_node.id.lower())
        full_path.reverse()

    elif isinstance(target, ast.Name):
        full_path.append(target.id.lower())

    elif isinstance(target, ast.Subscript):
        key = target.slice

        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            return

        full_path.append(key.value.lower())

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


def extract_candidates(code):
    """
    Yield candidate secret values extracted from Python source code.

    Supports:
    - normal string assignments
    - annotated string assignments
    - dictionary literals with string key/value pairs

    Syntax errors and unsupported assignment shapes are ignored.

    Args:
        code (str): Raw Python source code.

    Yields:
        Candidate: Extracted variable name, value, and line number.
    """
    tree = parse_ast(code)
    if tree is None:
        return

    for node in get_assignments(tree):
        if isinstance(node.value, ast.Dict):
            yield from extract_candidates_from_dict(node.value)
            continue

        value = extract_node_value(node)
        if value is None:
            continue

        yield from extract_assignment_candidates(node, value)