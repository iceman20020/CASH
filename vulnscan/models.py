from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any
import datetime as _dt


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, Enum):
    TENTATIVE = "tentative"
    FIRM = "firm"
    CERTAIN = "certain"

    @property
    def rank(self) -> int:
        return {"tentative": 0, "firm": 1, "certain": 2}[self.value]


_SEV_BY_CVSS = [
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
    (0.0, Severity.INFO),
]


def severity_from_cvss(score: float) -> Severity:
    for threshold, sev in _SEV_BY_CVSS:
        if score >= threshold:
            return sev
    return Severity.INFO


@dataclass
class Finding:
    tool: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.FIRM
    target: str = ""
    host: str = ""
    port: int | None = None
    url: str | None = None
    evidence: str = ""
    category: str = ""
    cwe: str | None = None
    cve: str | None = None
    cvss: float | None = None
    owasp_id: str = ""
    owasp_name: str = ""
    owasp_url: str = ""
    references: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d

    def dedupe_key(self) -> tuple[str, str, str, str]:
        return (
            self.host or self.target,
            str(self.port or ""),
            self.category or self.title,
            self.title,
        )


@dataclass
class ScanResult:
    target: str
    started_at: str = field(
        default_factory=lambda: _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
    )
    finished_at: str = ""
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def summary(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    def highest(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
