
import argparse
from collections import Counter
from pathlib import Path

from colored_print import log

from mauditor import __version__
from mauditor.core.auditor import Auditor
from mauditor.core.models import Severity


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mauditor",
        description="Master Auditor\n\nA Python security auditing tool",
    )

    parser.add_argument(
        "target",
        type=Path,
        help="Path of the Python project to analyze.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def print_header(target: Path) -> None:
    log.pink("=" * 60)
    log.pink("  MAUDITOR - PYTHON SECURITY AUDITOR")
    log.pink("=" * 60)

    log.info(f"Version: {__version__}")
    log.info(f"Target:  {target.resolve()}")
    log.success("\nStarting security analysis...\n")


def print_finding(index: int, finding) -> None:
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
    elif severity == Severity.LOW:
        log.info(severity_message)
    elif severity == Severity.INFO:
        log.info(severity_message)


def print_summary(findings: list) -> None:
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
        elif severity == Severity.LOW:
            log.info(message)
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

    if findings:
        for index, finding in enumerate(findings, start=1):
            print_finding(index, finding)
    else:
        log.success("\nNo security findings detected.")

    print_summary(findings)

    return 1 if findings else 0
