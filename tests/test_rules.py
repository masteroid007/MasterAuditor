
from pathlib import Path

from mauditor.core.models import DataAnalysis, Severity
from mauditor.core.rules import EvalRule


def create_analysis(calls):
    return DataAnalysis(
        file_path=Path("example.py"),
        info_calls=calls
    )


def test_eval_detected():
    analysis = create_analysis([
        {"name": "eval", "type": "Name", "line": 1}
    ])

    rule = EvalRule()
    findings = rule.check(analysis)

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC001"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file_path == Path("example.py")
    assert findings[0].line == 1


def test_attribute_eval_detected():
    analysis = create_analysis([
        {"name": "obj.eval", "type": "Attribute", "line": 3}
    ])

    rule = EvalRule()
    findings = rule.check(analysis)

    assert len(findings) == 1
    assert findings[0].line == 3


def test_multiple_eval_detected():
    analysis = create_analysis([
        {"name": "eval", "type": "Name", "line": 1},
        {"name": "eval", "type": "Name", "line": 5},
    ])

    rule = EvalRule()
    findings = rule.check(analysis)

    assert len(findings) == 2


def test_my_eval_not_detected():
    analysis = create_analysis([
        {"name": "my_eval", "type": "Name", "line": 1}
    ])

    rule = EvalRule()
    findings = rule.check(analysis)

    assert findings == []


def test_print_not_detected():
    analysis = create_analysis([
        {"name": "print", "type": "Name", "line": 1}
    ])

    rule = EvalRule()
    findings = rule.check(analysis)

    assert findings == []


def test_no_calls():
    analysis = create_analysis([])

    rule = EvalRule()
    findings = rule.check(analysis)

    assert findings == []