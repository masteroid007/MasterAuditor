from pathlib import Path

def analyze_file(file_path: Path):
    with open(file_path, "r") as file:
        content = file.read()

    return content

def analyze_files(dir_list):
    contents = {}
    for file in dir_list:
        analyzed_file = analyze_file(file)
        contents[file] = analyzed_file

    return contents
        