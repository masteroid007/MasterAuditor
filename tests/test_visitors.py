
import ast

from mauditor.core.visitors import (
    CallVisitor,
    FunctionVisitor,
    ImportVisitor,
    ImportFromVisitor,
    ClassVisitor,
    VariableVisitor,
)


CODE = """
import os
import sys as system
from pathlib import Path
from mauditor.core import scanner as sc

global_value = 10


def calculate(a, b=5):
    local_value: int = 20
    counter = 0
    counter += 5

    global global_value
    global_value = 30

    result = a + b
    print(result)
    os.system("echo test")

    return result


async def fetch_data(url):
    return url


class Example:
    def __init__(self):
        self.value = 100

    def run(self):
        calculate(1, 2)
"""


def get_tree():
    """Restituisce l'AST del codice di test."""
    return ast.parse(CODE)


def test_call_visitor():
    tree = get_tree()
    visitor = CallVisitor()
    visitor.visit(tree)

    assert len(visitor.calls) == 3
    assert any(call["name"] == "print" for call in visitor.calls)
    assert any(call["name"] == "os.system" for call in visitor.calls)
    assert any(call["name"] == "calculate" for call in visitor.calls)


def test_function_visitor():
    tree = get_tree()
    visitor = FunctionVisitor()
    visitor.visit(tree)

    names = [function["name"] for function in visitor.functions]

    assert "calculate" in names
    assert "fetch_data" in names
    assert "__init__" in names
    assert "run" in names


def test_import_visitor():
    tree = get_tree()
    visitor = ImportVisitor()
    visitor.visit(tree)

    modules = [item["module"] for item in visitor.imports]

    assert "os" in modules
    assert "sys" in modules


def test_import_from_visitor():
    tree = get_tree()
    visitor = ImportFromVisitor()
    visitor.visit(tree)

    modules = [item["module"] for item in visitor.imports_from]

    assert "pathlib" in modules
    assert "mauditor.core" in modules


def test_class_visitor():
    tree = get_tree()
    visitor = ClassVisitor()
    visitor.visit(tree)

    names = [class_info["name"] for class_info in visitor.classes]

    assert "Example" in names


def test_variable_visitor():
    tree = get_tree()
    visitor = VariableVisitor()
    visitor.visit(tree)

    names = [variable["name"] for variable in visitor.variables]

    assert "global_value" in names
    assert "local_value" in names
    assert "counter" in names
    assert "result" in names


if __name__ == "__main__":
    test_call_visitor()
    test_function_visitor()
    test_import_visitor()
    test_import_from_visitor()
    test_class_visitor()
    test_variable_visitor()

    print("All visitor tests passed!")
