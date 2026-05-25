"""
Base class shared by all vulnerability detectors.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class VulnerabilityFinding:
    """
    Standardised vulnerability finding object.

    Every detector returns a list of these so the rest of the pipeline
    has a uniform interface to work with.
    """
    name: str
    vuln_type: str
    severity: Severity
    explanation: str
    technical_description: str
    impact: str
    fix: List[str]
    owasp_mapping: str
    cve_references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    affected_url: Optional[str] = None
    affected_port: Optional[int] = None
    payload_used: Optional[str] = None
    response_snippet: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vuln_type": self.vuln_type,
            "severity": self.severity.value,
            "explanation": self.explanation,
            "technical_description": self.technical_description,
            "impact": self.impact,
            "fix": self.fix,
            "owasp_mapping": self.owasp_mapping,
            "cve_references": self.cve_references,
            "cvss_score": self.cvss_score,
            "affected_url": self.affected_url,
            "affected_port": self.affected_port,
            "payload_used": self.payload_used,
            "response_snippet": self.response_snippet,
        }
