from pathlib import Path
from detectors.find_secrets import detect_secrets

def check_path(input_path):
    path = Path(input_path)
    if path.is_dir():
        return path
    else:
        raise FileNotFoundError(f"'{input_path}' does not exist or is not a directory!")


# Recursively search the given path and return all .py files
def list_python_files(path):
    return list(path.rglob("*.py"))


def scan(files):
    if not files:
        print("No Python files found.")
        return
    number_of_files = len(files)
    print(f"Scanning {number_of_files} Python files...")

    findings = 0
    files = sorted(files)

    for file in files:
        found = False
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                vulnerability = detect_secrets(line)
                if vulnerability is not None:
                    if not found:
                        print("\n--- Findings ---\n")
                    print(f"[{vulnerability[1]}] {file}:{line_number} {vulnerability[0]} detected → {line}")
                    findings += 1
                    found = True
    print(f"\nTotal findings = {findings}")
