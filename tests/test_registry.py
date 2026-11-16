
import pytest

from mauditor.core.rules.base import BaseRule
from mauditor.core.rules.registry import Registry
from mauditor.core.models import DataAnalysis, Finding, Severity


class DummyRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="TEST001",
            description="Dummy test rule",
            severity=Severity.LOW
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return []


class AnotherDummyRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="TEST002",
            description="Another dummy test rule",
            severity=Severity.MEDIUM
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        return []


def test_register_rule():
    registry = Registry()

    registry.register("TEST001", DummyRule)

    assert registry.get_rule("TEST001") is DummyRule


def test_register_duplicate_rule():
    registry = Registry()

    registry.register("TEST001", DummyRule)

    with pytest.raises(ValueError):
        registry.register("TEST001", AnotherDummyRule)


def test_register_invalid_rule():
    registry = Registry()

    with pytest.raises(TypeError):
        registry.register("INVALID", str)


def test_register_non_class():
    registry = Registry()

    with pytest.raises(TypeError):
        registry.register("INVALID", DummyRule())


def test_register_invalid_rule_id_type():
    registry = Registry()

    with pytest.raises(TypeError):
        registry.register(123, DummyRule)


def test_register_empty_rule_id():
    registry = Registry()

    with pytest.raises(ValueError):
        registry.register("   ", DummyRule)


def test_register_strips_rule_id():
    registry = Registry()

    registry.register(" TEST001 ", DummyRule)

    assert registry.get_rule("TEST001") is DummyRule


def test_get_rule():
    registry = Registry()
    registry.register("TEST001", DummyRule)

    assert registry.get_rule("TEST001") is DummyRule


def test_get_unknown_rule():
    registry = Registry()

    assert registry.get_rule("UNKNOWN") is None


def test_get_rule_invalid_id_type():
    registry = Registry()

    with pytest.raises(TypeError):
        registry.get_rule(123)


def test_unregister_rule():
    registry = Registry()
    registry.register("TEST001", DummyRule)

    result = registry.unregister("TEST001")

    assert result is True
    assert registry.get_rule("TEST001") is None


def test_unregister_unknown_rule():
    registry = Registry()

    assert registry.unregister("UNKNOWN") is False


def test_unregister_invalid_id_type():
    registry = Registry()

    with pytest.raises(TypeError):
        registry.unregister(123)


def test_unregister_strips_rule_id():
    registry = Registry()
    registry.register("TEST001", DummyRule)

    assert registry.unregister(" TEST001 ") is True


def test_get_all_rules():
    registry = Registry()
    registry.register("TEST001", DummyRule)
    registry.register("TEST002", AnotherDummyRule)

    rules = registry.get_all_rules()

    assert rules == {
        "TEST001": DummyRule,
        "TEST002": AnotherDummyRule
    }


def test_get_all_rules_returns_copy():
    registry = Registry()
    registry.register("TEST001", DummyRule)

    rules = registry.get_all_rules()
    rules.clear()

    assert registry.get_rule("TEST001") is DummyRule
