from pathlib import Path
import ast

def analyze_file(file_path: Path):
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        return parse_file(content)

def analyze_files(dir_list):
    contents = {}
    for file in dir_list:
        analyzed_file = analyze_file(file)
        contents[file] = analyzed_file

    inspected_files = inspect_ast(contents)

    return inspected_files

def parse_file(content):
    try:
        return(ast.parse(content))
    except SyntaxError:
         return None

def inspect_ast(files):
    all_results = {}
    for file, tree in files.items():
        results = {
        "functions": 0,
        "classes": 0,
        "calls": 0,
        "imports": 0,
        "import_from": 0,
        "others": 0
        }
        if tree is not None:
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    results["functions"] += 1
                elif isinstance(node, ast.ClassDef):
                    results["classes"] += 1
                elif isinstance(node, ast.Call):
                    results["calls"] += 1
                elif isinstance(node, ast.Import):
                    results["imports"] += 1
                elif isinstance(node, ast.ImportFrom):
                    results["import_from"] += 1
                else:
                    results["others"] += 1
            all_results[file] = results
        else:
            all_results[file] = {"status": "not_analyzed", "reason": "SyntaxError"}

    return all_results