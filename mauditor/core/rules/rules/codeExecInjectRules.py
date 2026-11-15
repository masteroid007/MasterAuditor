from ..base import (
    BaseRule,
    _call_name,
    _has_keyword_argument,
    _is_string_literal,
    _keyword_arguments,
)
from mauditor.core.models import DataAnalysis
from mauditor.core.models import Finding, Severity

class EvalRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC001",
            description="Uso della funzione eval() rilevato.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if _call_name(call) == "eval":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings

class ExecRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC002",
            description="Uso della funzione exec() rilevato.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if _call_name(call) == "exec":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings

class CompileRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC003",
            description="Uso della funzione compile() rilevato.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if _call_name(call) == "compile":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings

class SubprocessShellRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC004",
            description="Uso di subprocess con shell=True rilevato.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if (
                _call_name(call) in {
                    "Popen",
                    "run",
                    "call",
                    "check_call",
                    "check_output",
                }
                and _has_keyword_argument(call.get("keywords", []), "shell", True)
            ):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings

class OsSystemRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC005",
            description="Uso di os.system() rilevato.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if _call_name(call) == "system":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings

class CommandInjectionRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC006",
            description="Possibile vulnerabilità di command injection rilevata.",
            severity=Severity.CRITICAL
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if _call_name(call) == "system" or (
                _call_name(call) in {
                    "Popen",
                    "run",
                    "call",
                    "check_call",
                    "check_output",
                }
                and _has_keyword_argument(call.get("keywords", []), "shell", True)
            ):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings

class SqlInjectionRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC007",
            description="Possibile vulnerabilità di SQL injection rilevata.",
            severity=Severity.CRITICAL
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if _call_name(call) in ["execute", "executemany"] and self._is_unsafe(call):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings

    @staticmethod
    def _is_unsafe(call) -> bool:
        args = call.get("args", [])
        keywords = _keyword_arguments(call)
        if not args:
            return False
        if len(args) > 1 or any(key in keywords for key in ("params", "parameters")):
            return False
        query = str(args[0]).strip()
        return not _is_string_literal(query)

class DynamicImportRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC008",
            description="Uso di import dinamico rilevato.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if _call_name(call) == "__import__":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings

class PickleRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC009",
            description="Uso di pickle rilevato.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if _call_name(call) in {"load", "loads"} and "pickle" in str(call.get("name", "")):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings

class UnsafeYamlLoadRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="SEC010",
            description="Uso di yaml.load() senza Loader specificato rilevato.",
            severity=Severity.HIGH
        )

    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        findings = []
        for call in data_analysis.info_calls:
            if (
                _call_name(call) == "load"
                and "yaml" in str(call.get("name", ""))
                and not _has_keyword_argument(call.get("keywords", []), "Loader")
            ):
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings