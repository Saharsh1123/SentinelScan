import ast
import textwrap

def parse_ast(file):
    """
    Parse source code into an AST.

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
    Yield all assignment nodes from an AST.

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
    Extract a string literal value from an assignment node.

    Args:
        node (ast.Assign): Assignment node.

    Returns:
        str | None: String value if valid, otherwise None.
    """
    val = node.value
    if not (isinstance(val, ast.Constant) and isinstance(val.value, str)):
        return None
    return val.value


def extract_variable_path(node):
    """
    Extract variable name paths from assignment targets.

    Supports simple variables and nested attributes (e.g., self.config.key).

    Args:
        node (ast.Assign): Assignment node.

    Yields:
        list[str]: Normalized variable path (lowercased components).
    """
    for var in node.targets:
        full_path = []
        temp_node = var

        # Traverse nested attribute chain (e.g., self.config.key)
        if isinstance(temp_node, ast.Attribute):
            while isinstance(temp_node, ast.Attribute):
                full_path.append(temp_node.attr.lower())
                temp_node = temp_node.value

            # Ensure root is a valid variable name
            if not isinstance(temp_node, ast.Name):
                continue

            full_path.append(temp_node.id.lower())
            full_path.reverse()

        # Handle simple variable assignment
        elif isinstance(var, ast.Name):
            full_path.append(var.id.lower())

        # Yield only valid, non-empty paths
        if len(full_path) != 0:
            yield full_path