from mauditor.core.models import DataAnalysis, Finding
from mauditor.core.rules.registry import Registry

class RulesEngine:
    def __init__(self, registry: Registry):
        self.registry = registry
        self.rules = [rule_class() for rule_class in self.registry.get_all_rules().values()]

    def run(self, data_analysis: DataAnalysis) -> list[Finding]:
        if data_analysis.status != "analyzed":
            return []

        findings: list[Finding] = []
        
        for rule in self.rules:
            findings.extend(rule.check(data_analysis))
        return findings