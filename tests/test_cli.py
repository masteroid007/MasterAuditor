import sys

import pytest

from mauditor.cli.arguments import main

def test_valid_directory(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["mauditor", str(tmp_path)]
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "validated successfully" in captured.out

def test_nonexistent_directory(monkeypatch, tmp_path):
    target = tmp_path / "missing"

    monkeypatch.setattr(
        sys,
        "argv",
        ["mauditor", str(target)]
    )

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2

def test_file_instead_of_directory(monkeypatch, tmp_path):
    target = tmp_path / "example.py"
    target.touch()

    monkeypatch.setattr(
        sys,
        "argv",
        ["mauditor", str(target)]
    )

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2
