import argparse

from scanner import list_python_files, scan

parser = argparse.ArgumentParser()
parser.add_argument("path")

args = parser.parse_args()

inputted_path = args.path

