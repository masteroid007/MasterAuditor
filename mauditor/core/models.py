from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

class Severity(Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass(frozen=True)
class Finding:
    rule_id: str
    message: str
    file_path: Path
    line: int
    severity: Severity

@dataclass
class ScanResult:
    target: Path
    scanned_files: int = 0
    findings: list[Finding] = field(default_factory=list)

@dataclass
class DataAnalysis:
    file_path: Path
    status: str = "analyzed"
    error: str | None = None
    variables: int = 0
    calls: int = 0
    functions: int = 0
    classes: int = 0
    imports: int = 0
    import_from: int = 0
    info_variables: list[dict] = field(default_factory=list)
    info_calls: list[dict] = field(default_factory=list)
    info_functions: list[dict] = field(default_factory=list)
    info_classes: list[dict] = field(default_factory=list)
    info_imports: list[dict] = field(default_factory=list)
    info_import_from: list[dict] = field(default_factory=list)
