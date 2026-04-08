from pathlib import Path

def list_python_files(path):
    return list(Path(path).rglob("*.py"))

def scan(path):
    files = list_python_files(path)
    number_of_files = len(files)
    print(f"Scanning {number_of_files} Python files...")
    print("--Results--")

    for file in files:
        line_count = 1
        with open(file, "r") as f:
            contents = f.readlines()
        print(f"\nFile: {file}")
        for line in contents:
            line = line.strip()
            print(f"Line {line_count}: {line}")
            line_count += 1
