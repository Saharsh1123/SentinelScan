from pathlib import Path


def check_path(input_path):
    path = Path(input_path)
    if path.is_dir():
        return path
    else:
        raise FileNotFoundError(f"'{input_path}' does not exist or is not a directory!")


# Recursively search the given path and return all .py files
def list_python_files(path):
    py_file_list = list(path.rglob("*.py"))
    return py_file_list


def scan(files):
    if not files:
        print("No Python files found.")
        return
    number_of_files = len(files)
    print(f"Scanning {number_of_files} Python files...")
    print("\n--- Findings ---")

    for file in files:
        line_count = 1
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            print(f"\nFile: {file}")
            for line in f:
                print(f"Line {line_count}: {line}", end="")
                line_count += 1
        print()
