from abc import ABC, abstractmethod
import re

from mauditor.core.models import DataAnalysis
from mauditor.core.models import Finding, Severity

class BaseRule(ABC):
    def __init__(self, rule_id: str, description: str, severity: Severity, cwe_id: str = "N/A", category: str = "General"):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity
        self.cwe_id = cwe_id
        self.category = category

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

def _call_name(call) -> str:
    """Return the unqualified name of a recorded call."""
    return str(call.get("name", "")).rsplit(".", 1)[-1]


def _has_keyword_argument(args, keyword: str, expected_value=None) -> bool:
    """Return whether call arguments contain the requested keyword/value."""
    if isinstance(args, dict):
        if keyword not in args:
            return False
        return expected_value is None or args[keyword] == expected_value

    if isinstance(args, list):
        for item in args:
            if not isinstance(item, dict) or keyword not in item:
                continue
            value = item[keyword]
            if expected_value is None or value == str(expected_value):
                return True
        return False

    arguments = str(args)
    if expected_value is None:
        return re.search(rf"\b{re.escape(keyword)}\s*=", arguments) is not None
    return re.search(
        rf"\b{re.escape(keyword)}\s*=\s*{re.escape(str(expected_value))}\b",
        arguments,
    ) is not None


def _keyword_arguments(call) -> dict[str, str]:
    """Return keyword arguments from a recorded call."""
    keywords = call.get("keywords", [])
    if isinstance(keywords, dict):
        return {str(key): str(value) for key, value in keywords.items()}
    if isinstance(keywords, list):
        result = {}
        for item in keywords:
            if isinstance(item, dict):
                result.update({str(key): str(value) for key, value in item.items()})
        return result
    return {}


def _is_string_literal(value) -> bool:
    """Return whether a recorded expression is a non-empty string literal."""
    expression = str(value).strip()
    if len(expression) < 2 or expression[0] in "fF":
        return False
    return expression[0] in "'\"" and expression[-1] == expression[0]