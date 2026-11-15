
from pathlib import Path
from tempfile import TemporaryDirectory

from mauditor.core.auditor import analyze_directory
from mauditor.core.models import DataAnalysis


def test_analyze_directory():
    with TemporaryDirectory() as directory:
        root = Path(directory)

        valid_file = root / "example.py"
        valid_file.write_text(
            "def hello():\n    print('Hello')",
            encoding="utf-8"
        )

        results = analyze_directory(root)

        assert str(valid_file) in results
        assert isinstance(results[str(valid_file)], DataAnalysis)
        assert results[str(valid_file)].status == "analyzed"
