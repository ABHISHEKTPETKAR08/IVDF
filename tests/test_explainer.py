"""
Tests for the VulnerabilityExplainer plain-English layer.
"""
import pytest

from backend.ai_explanations.explainer import (
    VulnerabilityExplainer,
    _PLAIN,
    _PLAIN_DEFAULT,
    _SEVERITY_BLURB,
)
from backend.detectors.base import Severity, VulnerabilityFinding


def _mock_finding(vuln_type="SQL Injection", severity=Severity.HIGH):
    return VulnerabilityFinding(
        name="Test",
        vuln_type=vuln_type,
        severity=severity,
        explanation="exp",
        technical_description="tech",
        impact="imp",
        fix=["step1"],
        owasp_mapping="A03:2021",
        cvss_score=8.0,
    )


class TestPlainEnglish:
    def test_explain_emits_non_technical_field(self):
        ex = VulnerabilityExplainer()
        out = ex.explain(_mock_finding())
        assert "non_technical" in out
        assert out["non_technical"] == _PLAIN["SQL Injection"]

    def test_explain_uses_default_for_unknown_type(self):
        ex = VulnerabilityExplainer()
        out = ex.explain(_mock_finding(vuln_type="Unknown Made Up Thing"))
        assert out["non_technical"] == _PLAIN_DEFAULT

    def test_severity_blurb_matches_severity(self):
        ex = VulnerabilityExplainer()
        for sev in Severity:
            out = ex.explain(_mock_finding(severity=sev))
            assert out["severity_blurb"] == _SEVERITY_BLURB[sev.value]

    def test_open_service_detected_has_plain_summary(self):
        """The nmap-derived INFO finding gets a plain summary."""
        ex = VulnerabilityExplainer()
        out = ex.explain(_mock_finding(
            vuln_type="Open Service Detected", severity=Severity.INFO,
        ))
        assert out["non_technical"] == _PLAIN["Open Service Detected"]
        assert "service" in out["non_technical"].lower()

    def test_nse_vulnerability_has_plain_summary(self):
        ex = VulnerabilityExplainer()
        out = ex.explain(_mock_finding(
            vuln_type="NSE Vulnerability", severity=Severity.HIGH,
        ))
        assert "patch" in out["non_technical"].lower() or \
               "vulner" in out["non_technical"].lower()


class TestExplainBatch:
    def test_batch_preserves_order(self):
        ex = VulnerabilityExplainer()
        findings = [
            _mock_finding(severity=Severity.CRITICAL),
            _mock_finding(severity=Severity.LOW),
        ]
        out = ex.explain_batch(findings)
        assert out[0]["severity"] == "CRITICAL"
        assert out[1]["severity"] == "LOW"


class TestRiskScore:
    def test_empty_zero(self):
        assert VulnerabilityExplainer().risk_score([]) == 0.0

    def test_critical_findings_high_score(self):
        ex = VulnerabilityExplainer()
        findings = [_mock_finding(severity=Severity.CRITICAL)] * 3
        for f in findings:
            f.cvss_score = 9.8
        score = ex.risk_score(findings)
        assert score >= 8.0

    def test_info_findings_low_score(self):
        ex = VulnerabilityExplainer()
        findings = [_mock_finding(severity=Severity.INFO)] * 3
        for f in findings:
            f.cvss_score = 0.0
        score = ex.risk_score(findings)
        assert score == 0.0
