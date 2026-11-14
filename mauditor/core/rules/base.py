from abc import ABC, abstractmethod

from mauditor.core.models import DataAnalysis
from mauditor.core.models import Finding, Severity

class BaseRule(ABC):
    def __init__(self, rule_id: str, description: str, severity: Severity):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity

    @abstractmethod
    def check(self, data_analysis: DataAnalysis) -> list[Finding]:
        """
        Verifica se ci sono violazioni della regola in base all'analisi dei dati.

        Args:
            data_analysis (DataAnalysis): Un oggetto DataAnalysis che contiene le informazioni sull'analisi del file.

        Returns:
            list[Finding]: Una lista di oggetti Finding che rappresentano le violazioni della regola.
        """
        pass

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
            if call["name"].split(".")[-1] == "eval":
                findings.append(Finding(
                    rule_id=self.rule_id,
                    message=self.description,
                    file_path=data_analysis.file_path,
                    line=call["line"],
                    severity=self.severity
                ))
        return findings