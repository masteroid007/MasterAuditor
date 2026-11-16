
from pathlib import Path

import pytest

from mauditor.core.models import DataAnalysis, Finding, Severity
from mauditor.core.rules.base import BaseRule
from mauditor.core.rules.engine import RulesEngine
from mauditor.core.rules.registry import Registry


class DummyRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="TEST001",
            description="Dummy test rule",
            severity=Severity.LOW,
        )
        self.executed = False

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        self.executed = True

        return [
            Finding(
                rule_id=self.rule_id,
                message="Dummy finding",
                file_path=data_analysis.file_path,
                line=1,
                severity=self.severity,
            )
        ]


class AnotherDummyRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="TEST002",
            description="Another dummy test rule",
            severity=Severity.HIGH,
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return [
            Finding(
                rule_id=self.rule_id,
                message="Another dummy finding",
                file_path=data_analysis.file_path,
                line=2,
                severity=self.severity,
            )
        ]


@pytest.fixture
def registry():
    registry = Registry()
    registry.register("TEST001", DummyRule)
    return registry


@pytest.fixture
def data_analysis():
    return DataAnalysis(file_path=Path("test.py"))


def test_run_single_rule(registry, data_analysis):
    engine = RulesEngine(registry)

    findings = engine.run(data_analysis)

    assert len(findings) == 1
    assert findings[0].rule_id == "TEST001"
    assert findings[0].message == "Dummy finding"
    assert findings[0].severity == Severity.LOW


def test_run_multiple_rules(registry, data_analysis):
    registry.register("TEST002", AnotherDummyRule)
    engine = RulesEngine(registry)

    findings = engine.run(data_analysis)

    assert len(findings) == 2
    assert {finding.rule_id for finding in findings} == {
        "TEST001",
        "TEST002",
    }


def test_run_with_empty_registry(data_analysis):
    registry = Registry()
    engine = RulesEngine(registry)

    findings = engine.run(data_analysis)

    assert findings == []


def test_run_with_unanalyzed_data(registry):
    engine = RulesEngine(registry)
    data_analysis = DataAnalysis(
        file_path=Path("test.py"),
        status="error",
    )

    findings = engine.run(data_analysis)

    assert findings == []


def test_rules_are_instantiated_once(registry):
    engine = RulesEngine(registry)

    first_instance = engine.rules[0]

    engine.run(DataAnalysis(file_path=Path("first.py")))
    engine.run(DataAnalysis(file_path=Path("second.py")))

    assert engine.rules[0] is first_instance