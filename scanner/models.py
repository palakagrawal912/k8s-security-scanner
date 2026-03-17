from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    check_id: str
    severity: Severity
    resource: str
    title: str
    detail: str
    remediation: str
    namespace: Optional[str] = None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned_pods: int = 0
    scanned_roles: int = 0
    scanned_bindings: int = 0

    @property
    def summary(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts
