from pathlib import Path
import ast

from mauditor.core.visitors import CallVisitor, FunctionVisitor, VariableVisitor, ClassVisitor, ImportVisitor, ImportFromVisitor

def analyze_file(file_path: Path):
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        return parse_file(content)

def analyze_files(file_paths):
    contents = {}
    for file in file_paths:
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
        results = {}
        if tree is not None:

            call_visitor = CallVisitor()
            function_visitor = FunctionVisitor()
            variable_visitor = VariableVisitor()
            class_visitor = ClassVisitor()
            import_visitor = ImportVisitor()
            import_from_visitor = ImportFromVisitor()

            function_visitor.visit(tree)
            call_visitor.visit(tree)
            variable_visitor.visit(tree)
            class_visitor.visit(tree)
            import_visitor.visit(tree)
            import_from_visitor.visit(tree)

            results["variables"], results["calls"], results["functions"], results["classes"], results["imports"], results["import_from"] = len(variable_visitor.variables), len(call_visitor.calls), len(function_visitor.functions), len(class_visitor.classes), len(import_visitor.imports), len(import_from_visitor.imports_from)

            results["info_variables"], results["info_calls"], results["info_functions"], results["info_classes"], results["info_imports"], results["info_import_from"] = variable_visitor.variables, call_visitor.calls, function_visitor.functions, class_visitor.classes, import_visitor.imports, import_from_visitor.imports_from
            all_results[file] = results
        else:
            all_results[file] = {"status": "not_analyzed", "reason": "SyntaxError"}

    return all_results