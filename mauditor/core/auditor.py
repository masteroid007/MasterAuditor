
from pathlib import Path

from mauditor.core.engine import analyze_files
from mauditor.core.models import DataAnalysis, Finding
from mauditor.core.rules.engine import RulesEngine
from mauditor.core.rules.registry import Registry
from mauditor.core.scanner import scan_directory


class Auditor:
    def __init__(self):
        self.registry = Registry.default()
        self.rules_engine = RulesEngine(self.registry)

    def analyze_directory(self, target: Path) -> dict[str, DataAnalysis]:
        files = scan_directory(target)
        results = analyze_files(files)

        return results

    def run(self, target: Path) -> list[Finding]:
        analyses = self.analyze_directory(target)

        findings: list[Finding] = []

        for data_analysis in analyses.values():
            findings.extend(self.rules_engine.run(data_analysis))

        return findings