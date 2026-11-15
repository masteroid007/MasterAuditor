"""Tests for the security rules exposed by :mod:`mauditor.core.rules`."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from mauditor.core.rules import (
    CommandInjectionRule,
    CompileRule,
    DynamicImportRule,
    EvalRule,
    ExecRule,
    HardcodedAccessTokenRule,
    HardcodedApiKeyRule,
    HardcodedClientSecretRule,
    HardcodedConnectionStringRule,
    HardcodedDatabaseCredentialsRule,
    HardcodedPasswordRule,
    HardcodedPrivateKeyRule,
    HardcodedRefreshTokenRule,
    HardcodedSecretKeyRule,
    HardcodedSecretRule,
    HardcodedTokenRule,
    OsSystemRule,
    PickleRule,
    SqlInjectionRule,
    SubprocessShellRule,
    UnsafeYamlLoadRule,
)


def make_analysis(*, variables=None, calls=None):
    """Create the minimum analysis object required by the rules."""
    return SimpleNamespace(
        file_path=Path("sample.py"),
        info_variables=variables or [],
        info_calls=calls or [],
    )


@pytest.mark.parametrize(
    ("rule", "call_name"),
    [
        (EvalRule, "eval"),
        (EvalRule, "module.eval"),
        (ExecRule, "exec"),
        (ExecRule, "module.exec"),
        (CompileRule, "compile"),
        (DynamicImportRule, "__import__"),
        (PickleRule, "pickle.load"),
        (PickleRule, "pickle.loads"),
        (UnsafeYamlLoadRule, "yaml.load"),
    ],
)
def test_call_rules_detect_dangerous_calls(rule, call_name):
    findings = rule().check(make_analysis(calls=[{"name": call_name, "line": 12}]))

    assert len(findings) == 1
    assert findings[0].file_path == Path("sample.py")
    assert findings[0].line == 12


@pytest.mark.parametrize(
    ("rule", "call_name"),
    [
        (EvalRule, "my_eval"),
        (ExecRule, "execute"),
        (CompileRule, "my_compile"),
        (DynamicImportRule, "import_module"),
        (PickleRule, "json.loads"),
        (UnsafeYamlLoadRule, "json.load"),
    ],
)
def test_call_rules_ignore_similar_calls(rule, call_name):
    assert rule().check(make_analysis(calls=[{"name": call_name, "line": 8}])) == []


@pytest.mark.parametrize("call_name", ["Popen", "subprocess.run", "call", "check_call", "check_output"])
def test_subprocess_shell_rule_requires_shell_true(call_name):
    matching = {"name": call_name, "keywords": [{"shell": "True"}], "line": 10}
    safe = {"name": call_name, "keywords": [{"shell": "False"}], "line": 11}

    findings = SubprocessShellRule().check(make_analysis(calls=[matching, safe]))

    assert [finding.line for finding in findings] == [10]


def test_subprocess_shell_rule_ignores_non_subprocess_calls():
    call = {"name": "other.execute", "keywords": [{"shell": "True"}], "line": 10}

    assert SubprocessShellRule().check(make_analysis(calls=[call])) == []


@pytest.mark.parametrize("rule", [OsSystemRule, CommandInjectionRule])
def test_system_calls_are_detected_by_system_and_injection_rules(rule):
    findings = rule().check(make_analysis(calls=[{"name": "os.system", "line": 14}]))

    assert len(findings) == 1
    assert findings[0].line == 14


def test_command_injection_rule_detects_shell_enabled_process_calls():
    call = {"name": "subprocess.run", "keywords": [{"shell": "True"}], "line": 15}

    assert CommandInjectionRule().check(make_analysis(calls=[call]))[0].line == 15


@pytest.mark.parametrize(
    ("call", "expected_lines"),
    [
        ({"name": "cursor.execute", "args": ["query"], "line": 20}, [20]),
        ({"name": "cursor.executemany", "args": ["query"], "line": 21}, [21]),
        ({"name": "cursor.execute", "args": ['"SELECT 1"'], "line": 22}, []),
        ({"name": "cursor.execute", "args": ["query", "params"], "line": 23}, []),
        (
            {
                "name": "cursor.execute",
                "args": ["query"],
                "keywords": [{"params": "params"}],
                "line": 24,
            },
            [],
        ),
    ],
)
def test_sql_injection_rule_distinguishes_unsafe_queries(call, expected_lines):
    findings = SqlInjectionRule().check(make_analysis(calls=[call]))

    assert [finding.line for finding in findings] == expected_lines


def test_unsafe_yaml_load_requires_loader_keyword():
    calls = [
        {"name": "yaml.load", "keywords": [], "line": 30},
        {"name": "yaml.load", "keywords": [{"Loader": "SafeLoader"}], "line": 31},
    ]

    findings = UnsafeYamlLoadRule().check(make_analysis(calls=calls))

    assert [finding.line for finding in findings] == [30]


HARD_CODED_RULES = [
    (HardcodedPasswordRule, {"password", "passwd", "pwd"}),
    (HardcodedSecretRule, {"secret"}),
    (HardcodedTokenRule, {"token"}),
    (HardcodedApiKeyRule, {"api_key"}),
    (HardcodedSecretKeyRule, {"secret_key"}),
    (HardcodedAccessTokenRule, {"access_token"}),
    (HardcodedRefreshTokenRule, {"refresh_token"}),
    (HardcodedClientSecretRule, {"client_secret"}),
    (HardcodedPrivateKeyRule, {"private_key"}),
    (HardcodedDatabaseCredentialsRule, {"db_credentials"}),
    (HardcodedConnectionStringRule, {"connection_string"}),
]


@pytest.mark.parametrize(("rule", "names"), HARD_CODED_RULES)
def test_hardcoded_rules_detect_string_literal_variables(rule, names):
    name = next(iter(names))
    variables = [{"name": name, "value": '"secret-value"', "line": 40}]

    findings = rule().check(make_analysis(variables=variables))

    assert len(findings) == 1
    assert findings[0].file_path == Path("sample.py")
    assert findings[0].line == 40


@pytest.mark.parametrize(("rule", "names"), HARD_CODED_RULES)
def test_hardcoded_rules_detect_string_literal_keyword_arguments(rule, names):
    name = next(iter(names))
    calls = [{"name": "connect", "keywords": [{name: "'secret-value'"}], "line": 41}]

    findings = rule().check(make_analysis(calls=calls))

    assert len(findings) == 1
    assert findings[0].line == 41


@pytest.mark.parametrize(("rule", "names"), HARD_CODED_RULES)
def test_hardcoded_rules_ignore_non_literals_and_unrelated_names(rule, names):
    name = next(iter(names))
    variables = [
        {"name": name, "value": "secret_value", "line": 42},
        {"name": "ordinary_text", "value": "'secret-value'", "line": 43},
    ]

    assert rule().check(make_analysis(variables=variables)) == []


def test_security_rules_return_no_findings_for_empty_analysis():
    rules = [
        EvalRule,
        ExecRule,
        CompileRule,
        SubprocessShellRule,
        OsSystemRule,
        CommandInjectionRule,
        SqlInjectionRule,
        DynamicImportRule,
        PickleRule,
        UnsafeYamlLoadRule,
        *(rule for rule, _ in HARD_CODED_RULES),
    ]

    analysis = make_analysis()

    for rule in rules:
        assert rule().check(analysis) == [], rule.__name__
