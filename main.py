from cli import input_path
from scanner import check_path, scan, list_python_files


if __name__ == "__main__":
    try:
        path = check_path(input_path)
        files = list_python_files(path)
        scan(files)
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")


