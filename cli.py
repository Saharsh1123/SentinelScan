import argparse

from scanner import list_python_files, scan

parser = argparse.ArgumentParser()
parser.add_argument("path")

args = parser.parse_args()

path = args.path

list_python_files(path)
scan(path)