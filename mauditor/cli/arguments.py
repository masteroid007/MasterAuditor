import argparse
from pathlib import Path

from mauditor import __version__
from mauditor.core.scanner import scan_directory


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mauditor",
        description="Master Auditor \n\nA Python security auditing tool"
    )

    parser.add_argument(
        "target",
        type=Path,
        help="Path of the Python project to analyze."
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )

    return parser


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    target = args.target

    if not target.exists():
        parser.error(f"Target does not exist: {target}")

    if not target.is_dir():
        parser.error(f"Target is not a directory: {target}")

    print(f"Mauditor v{__version__}")
    print(f"Target: {target.resolve()}")
    print("Target directory validated successfully.")

    files = scan_directory(target)

    return 0
