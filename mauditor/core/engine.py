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

    return contents

def parse_file(content):
    try:
        return(ast.parse(content))
    except SyntaxError:
         return None

def inspect_ast(tree: ast.AST):
    functions = 0
    classes = 0
    calls = 0
    imports = 0
    import_from = 0
    others = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions += 1
        elif isinstance(node, ast.ClassDef):
            classes += 1
        elif isinstance(node, ast.Call):
            calls += 1
        elif isinstance(node, ast.Import):
            imports += 1
        elif isinstance(node, ast.ImportFrom):
            import_from += 1
        else:
            others += 1