"""
HTTP Security-Header Checker.

Inspects HTTP response headers for missing or misconfigured security controls.
"""
import asyncio
from typing import Dict, List, Optional

import httpx

from backend.adaptive_scanner.adaptive_engine import evasion
from backend.detectors.base import Severity, VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Each entry: (header_name, recommended_value_hint, severity, owasp, cvss)
_REQUIRED_HEADERS: List[tuple] = [
    (
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
        Severity.HIGH,
        "A05:2021 – Security Misconfiguration",
        7.5,
        "Enforces HTTPS and prevents SSL-stripping attacks.",
    ),
    (
        "X-Content-Type-Options",
        "nosniff",
        Severity.MEDIUM,
        "A05:2021 – Security Misconfiguration",
        5.3,
        "Prevents MIME-type sniffing attacks.",
    ),
    (
        "X-Frame-Options",
        "DENY or SAMEORIGIN",
        Severity.MEDIUM,
        "A05:2021 – Security Misconfiguration",
        6.1,
        "Protects against Clickjacking attacks.",
    ),
    (
        "Content-Security-Policy",
        "default-src 'self'",
        Severity.HIGH,
        "A03:2021 – Injection",
        7.2,
        "Prevents XSS and data-injection attacks.",
    ),
    (
        "X-XSS-Protection",
        "1; mode=block",
        Severity.LOW,
        "A03:2021 – Injection",
        4.3,
        "Enables browser-level XSS filter (legacy browsers).",
    ),
    (
        "Referrer-Policy",
        "no-referrer or strict-origin-when-cross-origin",
        Severity.LOW,
        "A05:2021 – Security Misconfiguration",
        3.7,
        "Controls how much referrer information is sent.",
    ),
    (
        "Permissions-Policy",
        "geolocation=(), microphone=(), camera=()",
        Severity.LOW,
        "A05:2021 – Security Misconfiguration",
        3.5,
        "Restricts powerful browser features from being used.",
    ),
]

_DANGEROUS_HEADERS = [
    ("Server", "Reveals server software and version."),
    ("X-Powered-By", "Reveals framework/technology stack."),
    ("X-AspNet-Version", "Reveals ASP.NET version."),
]


class HeaderChecker:
    """Analyse HTTP response headers for security misconfigurations."""

    REQUEST_TIMEOUT = 6.0

    async def detect(self, url: str) -> List[VulnerabilityFinding]:
        """Fetch *url* headers and return a list of findings."""
        findings: List[VulnerabilityFinding] = []
        try:
            async with httpx.AsyncClient(
                timeout=self.REQUEST_TIMEOUT,
                verify=False,
                follow_redirects=True,
            ) as client:
                resp = await client.head(url, headers=evasion.headers(include_referer=False))
                headers = {k.lower(): v for k, v in resp.headers.items()}

            findings.extend(self._check_missing(headers, url))
            findings.extend(self._check_information_disclosure(headers, url))

        except httpx.RequestError as exc:
            logger.warning("Header check failed for %s: %s", url, exc)

        return findings

    def _check_missing(
        self, headers: Dict[str, str], url: str
    ) -> List[VulnerabilityFinding]:
        findings = []
        for header, hint, severity, owasp, cvss, note in _REQUIRED_HEADERS:
            if header.lower() not in headers:
                findings.append(
                    VulnerabilityFinding(
                        name=f"Missing Security Header: {header}",
                        vuln_type="Missing Security Header",
                        severity=severity,
                        explanation=(
                            f"The HTTP response does not include the '{header}' header. "
                            f"{note}"
                        ),
                        technical_description=(
                            f"Header '{header}' is absent from the server response for {url}."
                        ),
                        impact=note,
                        fix=[
                            f"Add the header: {header}: {hint}",
                            "Configure web-server (nginx/Apache) to send this header globally.",
                            "Consider using a security-header middleware in your framework.",
                        ],
                        owasp_mapping=owasp,
                        cvss_score=cvss,
                        affected_url=url,
                    )
                )
        return findings

    def _check_information_disclosure(
        self, headers: Dict[str, str], url: str
    ) -> List[VulnerabilityFinding]:
        findings = []
        for header, description in _DANGEROUS_HEADERS:
            val = headers.get(header.lower())
            if val:
                findings.append(
                    VulnerabilityFinding(
                        name=f"Information Disclosure via {header} Header",
                        vuln_type="Information Disclosure",
                        severity=Severity.LOW,
                        explanation=(
                            f"The '{header}: {val}' header leaks technology information "
                            "that assists attackers in targeting known vulnerabilities."
                        ),
                        technical_description=description,
                        impact=(
                            "Attackers learn the server stack and can search for version-"
                            "specific exploits."
                        ),
                        fix=[
                            f"Remove or suppress the '{header}' header.",
                            "Configure ServerTokens Off (Apache) or server_tokens off (nginx).",
                        ],
                        owasp_mapping="A05:2021 – Security Misconfiguration",
                        cvss_score=3.1,
                        affected_url=url,
                        response_snippet=f"{header}: {val}",
                    )
                )
        return findings
