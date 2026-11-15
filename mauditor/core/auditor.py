from pathlib import Path

from mauditor.core.scanner import scan_directory
from mauditor.core.engine import analyze_files

def analyze_directory(target: Path):
    files = scan_directory(target)
    results = analyze_files(files)

    return results
