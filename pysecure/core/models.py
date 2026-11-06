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

