import argparse
from collections import Counter
from pathlib import Path
from colored_print import log

from mauditor import __version__
from mauditor.core.auditor import Auditor
from mauditor.core.models import Finding, Severity


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="maudit",
        description=(
            "Mauditor - Python Security Auditor\n\n"
            "A static analysis tool designed to identify potential "
            "security vulnerabilities in Python projects."
        ),
        epilog=(
            "Examples:\n"
            "  maudit ./my-project\n"
            "  maudit /path/to/project\n"
            "  maudit --version\n\n"
            "Project:\n"
            "  https://github.com/masteroid007/MasterAuditor"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target",
        type=Path,
        metavar="TARGET",
        help="Path to the Python project to analyze.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show the program's version number and exit.",
    )

    return parser


def print_header(target: Path) -> None:
    log.pink("=" * 60)
    log.pink("  MAUDITOR - PYTHON SECURITY AUDITOR")
    log.pink("=" * 60)

    log.info(f"Version: {__version__}")
    log.info(f"Target:  {target.resolve()}")
    log.success("\nStarting security analysis...\n")


def print_finding(index: int, finding: Finding) -> None:
    log("-" * 60)

    log.info(f"Finding #{index}")
    log(f"Rule ID:  {finding.rule_id}")
    log(f"Message:  {finding.message}")
    log(f"Location: {finding.file_path}:{finding.line}")

    severity = finding.severity
    severity_message = f"Severity: {severity.name}"

    if severity == Severity.CRITICAL:
        log.critical(severity_message)
    elif severity == Severity.HIGH:
        log.error(severity_message)
    elif severity == Severity.MEDIUM:
        log.warning(severity_message)
    else:
        log.info(severity_message)


def print_summary(findings: list[Finding]) -> None:
    log("\n" + "=" * 60)
    log.pink("  SCAN SUMMARY")
    log("=" * 60)

    total = len(findings)
    log(f"Total findings: {total}")

    counts = Counter(finding.severity for finding in findings)

    for severity in Severity:
        count = counts.get(severity, 0)
        message = f"{severity.name:<10}: {count}"

        if severity == Severity.CRITICAL:
            log.critical(message)
        elif severity == Severity.HIGH:
            log.error(message)
        elif severity == Severity.MEDIUM:
            log.warning(message)
        else:
            log.info(message)

    log("=" * 60)

    if total == 0:
        log.success("No findings found. Your scan completed successfully.")
    else:
        log.warning(f"Scan completed with {total} finding(s).")


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    target = args.target

    if not target.exists():
        parser.error(f"Target does not exist: {target}")

    if not target.is_dir():
        parser.error(f"Target is not a directory: {target}")

    print_header(target)

    findings = Auditor().run(target)

    for index, finding in enumerate(findings, start=1):
        print_finding(index, finding)

    print_summary(findings)

    return 1 if findings else 0
