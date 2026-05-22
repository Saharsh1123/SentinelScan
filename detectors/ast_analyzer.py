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
        tree = ast.parse(file)
    except SyntaxError:
        return None

    return tree


def get_assignments(tree):
    """
    Yield assignment nodes from a parsed AST.

    Args:
        tree (ast.AST): Parsed syntax tree.

    Yields:
        ast.Assign: Assignment nodes found during traversal.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            yield node


def extract_node_value(node):
    """
    Extract a string literal from an assignment node.

    Non-string assignments are ignored because the current detector only
    evaluates hardcoded string values.

    Args:
        node (ast.Assign): Assignment node.

    Returns:
        str | None: Extracted string value, or None if unsupported.
    """
    val = node.value
    if not (isinstance(val, ast.Constant) and isinstance(val.value, str)):
        return None
    return val.value


def extract_variable_path(node):
    """
    Extract normalized variable paths from assignment targets.

    Supports simple variables and nested attributes, such as:
    `password` and `self.config.password`.

    Args:
        node (ast.Assign): Assignment node.

    Yields:
        list[str]: Lowercased variable path components.
    """
    for var in node.targets:
        full_path = []
        temp_node = var

        # Walk nested attributes from right to left.
        if isinstance(temp_node, ast.Attribute):
            while isinstance(temp_node, ast.Attribute):
                full_path.append(temp_node.attr.lower())
                temp_node = temp_node.value

            # Ignore unsupported roots such as function calls or subscripts.
            if not isinstance(temp_node, ast.Name) or isinstance(temp_node, ast.Subscript):
                continue

            full_path.append(temp_node.id.lower())
            full_path.reverse()

        # Handle direct variable assignment.
        elif isinstance(var, ast.Name):
            full_path.append(var.id.lower())
        
        elif isinstance(var, ast.Subscript):
            key = var.slice

            if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                continue

            full_path.append(key.value.lower())
            
        if full_path:
            yield full_path


def extract_candidates(code):
    """
    Yield candidate secret values extracted from Python source code.

    Each candidate represents a string assignment that can be evaluated by
    the rule engine. Syntax errors and unsupported assignments are ignored.

    Args:
        code (str): Raw Python source code.

    Yields:
        Candidate: Extracted variable name, value, and line number.
    """
    tree = parse_ast(code)
    if tree is None:
        return

    for node in get_assignments(tree):
        val = extract_node_value(node)
        if val is None:
            continue

        line_number = node.lineno

        for full_path in extract_variable_path(node):
            var_name = full_path[-1]

            yield Candidate(
                line_number=line_number,
                var_name=var_name,
                value=val,
            )