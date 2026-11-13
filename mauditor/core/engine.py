from pathlib import Path
import ast

from mauditor.core.visitors import CallVisitor, FunctionVisitor, VariableVisitor, ClassVisitor, ImportVisitor, ImportFromVisitor
from mauditor.core.models import DataAnalysis

def analyze_file(file_path: Path):
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()

            return parse_file(content)
        except FileNotFoundError:
            return None, f"File not found: {file_path}"
        except PermissionError:
            return None, f"Permission denied: {file_path}"
        except UnicodeDecodeError:
            return None, f"Cannot decode file: {file_path}"
        except OSError as e:
            return None, f"OS error: {e}"

def analyze_files(file_paths):
    contents = {}
    for file in file_paths:
        analyzed_file = analyze_file(file)
        contents[file] = analyzed_file

    inspected_files = inspect_ast(contents)
    return inspected_files

def parse_file(content):
    try:
        return ast.parse(content), None
    except SyntaxError as e:
         return None, f"Syntax error: {e}"
    except ValueError as e:
        return None, f"Value error: {e}"

def inspect_ast(files):
    all_results = {}
    for file, (tree, error) in files.items():
        if tree is not None:

            analysis = DataAnalysis(file_path=file)

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

            analysis.variables, analysis.calls, analysis.functions, analysis.classes, analysis.imports, analysis.import_from = len(variable_visitor.variables), len(call_visitor.calls), len(function_visitor.functions), len(class_visitor.classes), len(import_visitor.imports), len(import_from_visitor.imports_from)
            
            analysis.info_variables, analysis.info_calls, analysis.info_functions, analysis.info_classes, analysis.info_imports, analysis.info_import_from = variable_visitor.variables, call_visitor.calls, function_visitor.functions, class_visitor.classes, import_visitor.imports, import_from_visitor.imports_from

        else:
            analysis = DataAnalysis(
                file_path=file, 
                status="not_analyzed", 
                error=error
                )

        all_results[file] = analysis

    return all_results