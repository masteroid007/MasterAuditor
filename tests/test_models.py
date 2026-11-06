from pathlib import Path 

from pysecure.core.models import Finding, ScanResult, Severity

def test_finding_creation():
    finding = Finding(
        rule_id="PS001",
        message="Potential hardcoded credential",
        file_path=Path("config.py"),
        line=10,
        severity=Severity.HIGH,
        )

    assert finding.rule_id == "PS001"
    assert finding.line == 10
    assert finding.severity == Severity.HIGH

def test_scan_result_creation():
    result = ScanResult(target=Path("."))

    assert result.scanned_files == 0
    assert result.findings == []

def test_scan_results_have_independent_findings():
    first = ScanResult(target=Path("project1"))
    second = ScanResult(target=Path("project2"))

    first.findings.append(
        Finding(
            rule_id="PS001",
            message="Test finding",
            file_path=Path("config.py"),
            line=1,
            severity=Severity.HIGH
        )
    )

    assert len(first.findings) == 1
    assert len(second.findings) == 0