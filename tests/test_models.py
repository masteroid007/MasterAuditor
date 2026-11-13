from pathlib import Path
from dataclasses import FrozenInstanceError

from mauditor.core.models import Severity, Finding, ScanResult, DataAnalysis


def test_severity():
    assert Severity.INFO.value == "INFO"
    assert Severity.LOW.value == "LOW"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"


def test_finding():
    finding = Finding(
        rule_id="MAU001",
        message="Potentially unsafe call",
        file_path=Path("example.py"),
        line=12,
        severity=Severity.HIGH,
    )

    assert finding.rule_id == "MAU001"
    assert finding.message == "Potentially unsafe call"
    assert finding.file_path == Path("example.py")
    assert finding.line == 12
    assert finding.severity is Severity.HIGH


def test_finding_is_immutable():
    finding = Finding(
        rule_id="MAU002",
        message="Test finding",
        file_path=Path("test.py"),
        line=1,
        severity=Severity.INFO,
    )

    try:
        finding.message = "Changed message"
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("Finding should be immutable")


def test_scan_result_defaults():
    result = ScanResult(target=Path("project"))

    assert result.target == Path("project")
    assert result.scanned_files == 0
    assert result.findings == []


def test_scan_result_stores_findings():
    finding = Finding(
        rule_id="MAU003",
        message="Example",
        file_path=Path("main.py"),
        line=4,
        severity=Severity.MEDIUM,
    )
    result = ScanResult(
        target=Path("."),
        scanned_files=1,
        findings=[finding],
    )

    assert result.scanned_files == 1
    assert len(result.findings) == 1
    assert result.findings[0] == finding


def test_scan_results_have_independent_lists():
    first = ScanResult(target=Path("first"))
    second = ScanResult(target=Path("second"))

    first.findings.append(
        Finding(
            rule_id="MAU004",
            message="Only in first result",
            file_path=Path("first.py"),
            line=2,
            severity=Severity.LOW,
        )
    )

    assert len(first.findings) == 1
    assert second.findings == []


def test_data_analysis_defaults():
    analysis = DataAnalysis(file_path=Path("main.py"))

    assert analysis.file_path == Path("main.py")
    assert analysis.status == "analyzed"
    assert analysis.error is None

    assert analysis.variables == 0
    assert analysis.calls == 0
    assert analysis.functions == 0
    assert analysis.classes == 0
    assert analysis.imports == 0
    assert analysis.import_from == 0

    assert analysis.info_variables == []
    assert analysis.info_calls == []
    assert analysis.info_functions == []
    assert analysis.info_classes == []
    assert analysis.info_imports == []
    assert analysis.info_import_from == []


def test_data_analysis_stores_statistics_and_details():
    analysis = DataAnalysis(
        file_path=Path("module.py"),
        variables=2,
        calls=1,
        functions=1,
        classes=1,
        imports=1,
        import_from=1,
        info_variables=[{"name": "value"}],
        info_calls=[{"name": "print"}],
        info_functions=[{"name": "run"}],
        info_classes=[{"name": "Analyzer"}],
        info_imports=[{"module": "os"}],
        info_import_from=[{"module": "pathlib"}],
    )

    assert analysis.variables == len(analysis.info_variables) + 1
    assert analysis.calls == len(analysis.info_calls)
    assert analysis.functions == len(analysis.info_functions)
    assert analysis.classes == len(analysis.info_classes)
    assert analysis.imports == len(analysis.info_imports)
    assert analysis.import_from == len(analysis.info_import_from)


def test_data_analysis_can_represent_failed_analysis():
    analysis = DataAnalysis(
        file_path=Path("broken.py"),
        status="not_analyzed",
        error="Syntax error",
    )

    assert analysis.status == "not_analyzed"
    assert analysis.error == "Syntax error"
    assert analysis.variables == 0
    assert analysis.info_variables == []


if __name__ == "__main__":
    test_severity()
    test_finding()
    test_finding_is_immutable()
    test_scan_result_defaults()
    test_scan_result_stores_findings()
    test_scan_results_have_independent_lists()
    test_data_analysis_defaults()
    test_data_analysis_stores_statistics_and_details()
    test_data_analysis_can_represent_failed_analysis()

    print("All model tests passed!")
