"""
ReportGenerator coverage — JSON / CSV / PDF.
"""
import json
import os
from pathlib import Path

import pytest

from backend.reports.report_generator import ReportGenerator


@pytest.fixture
def scan_data():
    return {
        "metadata": {
            "scan_id": "abc12345-0000-0000-0000-000000000000",
            "target": "127.0.0.1",
            "scan_type": "safe",
            "started_at": "2026-05-24T10:00:00Z",
            "completed_at": "2026-05-24T10:02:00Z",
            "duration": "120s",
            "risk_score": 7.4,
        },
        "severity_summary": {
            "CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5,
        },
        "vulnerabilities": [
            {
                "name": "Missing Security Header: HSTS",
                "vuln_type": "Missing Security Header",
                "severity": "HIGH",
                "cvss_score": 7.5,
                "owasp_mapping": "A05:2021",
                "affected_url": "http://127.0.0.1",
                "explanation": "HSTS not present.",
                "impact": "MITM possible.",
                "fix": ["Add HSTS header"],
            },
            {
                "name": "Reflected XSS",
                "vuln_type": "XSS",
                "severity": "HIGH",
                "cvss_score": 8.8,
                "owasp_mapping": "A03:2021",
                "affected_url": "http://127.0.0.1/search",
                "explanation": "Reflected XSS in `q`.",
                "impact": "Session hijacking.",
                "fix": ["HTML-encode output"],
            },
        ],
    }


class TestReportGenerator:
    def test_json_report_writes_valid_file(self, scan_data, tmp_path):
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate_json(scan_data)
        assert os.path.exists(path)
        with open(path) as fh:
            loaded = json.load(fh)
        assert loaded["metadata"]["scan_id"].startswith("abc12345")
        assert len(loaded["vulnerabilities"]) == 2

    def test_csv_report_has_header_and_rows(self, scan_data, tmp_path):
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate_csv(scan_data)
        assert os.path.exists(path)
        text = Path(path).read_text()
        assert "name,vuln_type,severity" in text
        assert "Missing Security Header: HSTS" in text
        assert "Reflected XSS" in text

    def test_pdf_report_writes_file(self, scan_data, tmp_path):
        gen = ReportGenerator(output_dir=str(tmp_path))
        try:
            path = gen.generate_pdf(scan_data)
        except RuntimeError as exc:
            pytest.skip(f"reportlab not installed: {exc}")
        assert os.path.exists(path)
        assert os.path.getsize(path) > 100  # at least a real PDF, not empty

    def test_empty_vulnerabilities_renders(self, tmp_path):
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate_json({
            "metadata": {"scan_id": "x"}, "severity_summary": {},
            "vulnerabilities": [],
        })
        assert os.path.exists(path)
