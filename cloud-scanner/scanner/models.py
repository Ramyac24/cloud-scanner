"""
models.py
Core data models for the cloud misconfiguration scanner.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    def score(self) -> int:
        return {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}[self.value]

    def color(self) -> str:
        return {
            "CRITICAL": "bold red",
            "HIGH":     "red",
            "MEDIUM":   "yellow",
            "LOW":      "cyan",
            "INFO":     "dim",
        }[self.value]


class ScanType(str, Enum):
    TERRAFORM = "terraform"
    SECRET    = "secret"


@dataclass
class Finding:
    rule_id:      str
    title:        str
    severity:     Severity
    scan_type:    ScanType
    file_path:    str
    line_number:  Optional[int]
    resource:     Optional[str]       # e.g. aws_s3_bucket.my_bucket
    description:  str
    evidence:     str                 # the actual offending code/value
    remediation:  str                 # static fix hint

    # AI-populated fields (filled after LLM analysis)
    ai_explanation:  Optional[str] = None
    ai_fix:          Optional[str] = None
    ai_risk_score:   Optional[int] = None   # 1-10

    def to_dict(self) -> dict:
        return {
            "rule_id":       self.rule_id,
            "title":         self.title,
            "severity":      self.severity.value,
            "scan_type":     self.scan_type.value,
            "file_path":     self.file_path,
            "line_number":   self.line_number,
            "resource":      self.resource,
            "description":   self.description,
            "evidence":      self.evidence,
            "remediation":   self.remediation,
            "ai_explanation":self.ai_explanation,
            "ai_fix":        self.ai_fix,
            "ai_risk_score": self.ai_risk_score,
        }


@dataclass
class ScanResult:
    scan_id:    str
    target:     str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    findings:   list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    errors:     list[str] = field(default_factory=list)

    def add(self, finding: Finding):
        self.findings.append(finding)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def critical(self):  return self.by_severity(Severity.CRITICAL)
    def high(self):      return self.by_severity(Severity.HIGH)
    def medium(self):    return self.by_severity(Severity.MEDIUM)

    @property
    def risk_score(self) -> int:
        """Aggregate risk score across all findings."""
        return sum(f.severity.score() for f in self.findings)

    @property
    def summary(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return {
            "total":      len(self.findings),
            "risk_score": self.risk_score,
            "by_severity": counts,
            "files_scanned": self.files_scanned,
        }

    def to_dict(self) -> dict:
        return {
            "scan_id":      self.scan_id,
            "target":       self.target,
            "started_at":   self.started_at,
            "summary":      self.summary,
            "findings":     [f.to_dict() for f in self.findings],
            "errors":       self.errors,
        }
