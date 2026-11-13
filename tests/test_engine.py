from pathlib import Path
from tempfile import TemporaryDirectory

from mauditor.core.engine import (
    analyze_file,
    analyze_files,
    parse_file,
    inspect_ast,
)
from mauditor.core.models import DataAnalysis


CODE = """
import os
from pathlib import Path

global_value = 10

def calculate(value):
    result = value + 5
    print(result)
    os.getcwd()
    return result

class Example:
    def run(self):
        return calculate(10)
"""


def test_parse_file_valid_code():
    tree, error = parse_file(CODE)

    assert tree is not None
    assert error is None


def test_parse_file_invalid_code():
    tree, error = parse_file("def broken(:\n    pass")

    assert tree is None
    assert error is not None
    assert "Syntax error" in error


def test_analyze_file_valid_file():
    with TemporaryDirectory() as directory:
        file_path = Path(directory) / "valid.py"
        file_path.write_text(CODE, encoding="utf-8")

        tree, error = analyze_file(file_path)

        assert tree is not None
        assert error is None


def test_analyze_file_missing_file():
    with TemporaryDirectory() as directory:
        file_path = Path(directory) / "missing.py"

        tree, error = analyze_file(file_path)

        assert tree is None
        assert error is not None
        assert "File not found" in error


def test_inspect_ast_valid_tree():
    tree, error = parse_file(CODE)
    assert tree is not None
    assert error is None

    results = inspect_ast({Path("sample.py"): (tree, error)})

    assert Path("sample.py") in results
    analysis = results[Path("sample.py")]

    assert isinstance(analysis, DataAnalysis)
    assert analysis.status == "analyzed"
    assert analysis.error is None

    assert analysis.variables == len(analysis.info_variables)
    assert analysis.calls == len(analysis.info_calls)
    assert analysis.functions == len(analysis.info_functions)
    assert analysis.classes == len(analysis.info_classes)
    assert analysis.imports == len(analysis.info_imports)
    assert analysis.import_from == len(analysis.info_import_from)

    assert analysis.functions > 0
    assert analysis.classes > 0
    assert analysis.calls > 0


def test_inspect_ast_failed_parse():
    error_message = "Syntax error: invalid syntax"
    results = inspect_ast({Path("broken.py"): (None, error_message)})

    analysis = results[Path("broken.py")]

    assert isinstance(analysis, DataAnalysis)
    assert analysis.status == "not_analyzed"
    assert analysis.error == error_message


def test_analyze_files_continues_after_invalid_file():
    with TemporaryDirectory() as directory:
        root = Path(directory)
        valid_file = root / "valid.py"
        invalid_file = root / "invalid.py"
        missing_file = root / "missing.py"

        valid_file.write_text(CODE, encoding="utf-8")
        invalid_file.write_text("def broken(:\n    pass", encoding="utf-8")

        results = analyze_files([valid_file, invalid_file, missing_file])
        normalized_results = {
            Path(path): analysis for path, analysis in results.items()
        }

        assert set(normalized_results) == {
            valid_file,
            invalid_file,
            missing_file,
        }

        def result_for(path):
            return normalized_results[path]

        assert result_for(valid_file).status == "analyzed"
        assert result_for(valid_file).error is None

        assert result_for(invalid_file).status == "not_analyzed"
        assert result_for(invalid_file).error is not None

        assert result_for(missing_file).status == "not_analyzed"
        assert "File not found" in result_for(missing_file).error


if __name__ == "__main__":
    test_parse_file_valid_code()
    test_parse_file_invalid_code()
    test_analyze_file_valid_file()
    test_analyze_file_missing_file()
    test_inspect_ast_valid_tree()
    test_inspect_ast_failed_parse()
    test_analyze_files_continues_after_invalid_file()

    print("All engine tests passed!")
