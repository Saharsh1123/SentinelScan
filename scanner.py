from pathlib import Path

def list_python_files(inputted_path):
    return list(Path(inputted_path).rglob("*.py"))

def scan(inputted_path):
    files = list_python_files(inputted_path)
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
