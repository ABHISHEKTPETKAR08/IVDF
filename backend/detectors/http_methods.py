"""
Insecure HTTP Methods Checker.

Detects whether the server allows dangerous HTTP methods (PUT, DELETE, TRACE,
CONNECT, PATCH) that could be abused for Cross-Site Tracing (XST) or
unauthorised file manipulation.
"""
import asyncio
from typing import List

import httpx

from backend.adaptive_scanner.adaptive_engine import evasion
from backend.detectors.base import Severity, VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)

_DANGEROUS_METHODS = {
    "TRACE": (
        Severity.MEDIUM,
        "Enables Cross-Site Tracing (XST) attacks that bypass HttpOnly cookie protections.",
        "A05:2021 – Security Misconfiguration",
        5.8,
        ["CVE-2004-2320"],
    ),
    "PUT": (
        Severity.HIGH,
        "Allows arbitrary file uploads to the server filesystem.",
        "A01:2021 – Broken Access Control",
        8.1,
        [],
    ),
    "DELETE": (
        Severity.HIGH,
        "Allows deletion of server-side resources.",
        "A01:2021 – Broken Access Control",
        8.1,
        [],
    ),
    "CONNECT": (
        Severity.MEDIUM,
        "May enable open-proxy abuse for SSRF or traffic tunnelling.",
        "A05:2021 – Security Misconfiguration",
        6.1,
        [],
    ),
}

_OPTIONS_CHECK = True   # Always probe OPTIONS first to enumerate allowed methods


class HTTPMethodChecker:
    """Detect insecure HTTP methods enabled on the target endpoint."""

    REQUEST_TIMEOUT = 6.0

    async def detect(self, url: str) -> List[VulnerabilityFinding]:
        """Check which dangerous HTTP methods are accepted by *url*."""
        findings: List[VulnerabilityFinding] = []

        async with httpx.AsyncClient(
            timeout=self.REQUEST_TIMEOUT, verify=False, follow_redirects=False
        ) as client:
            # Enumerate via OPTIONS first
            allowed_from_options = await self._options_probe(client, url)

            # Directly probe each dangerous method
            for method, (severity, reason, owasp, cvss, cves) in _DANGEROUS_METHODS.items():
                accepted = await self._probe_method(client, url, method)
                if accepted or method in allowed_from_options:
                    findings.append(
                        VulnerabilityFinding(
                            name=f"Insecure HTTP Method Enabled: {method}",
                            vuln_type="Insecure HTTP Methods",
                            severity=severity,
                            explanation=f"The server accepts the {method} HTTP method. {reason}",
                            technical_description=(
                                f"Direct {method} request to {url} returned a non-405 status, "
                                "or method appeared in OPTIONS Allow header."
                            ),
                            impact=reason,
                            fix=[
                                f"Disable the {method} method in web-server configuration.",
                                "For Apache: use <LimitExcept GET POST> block.",
                                "For nginx: use `limit_except GET POST { deny all; }`.",
                                "Return HTTP 405 Method Not Allowed for all unused methods.",
                            ],
                            owasp_mapping=owasp,
                            cve_references=cves,
                            cvss_score=cvss,
                            affected_url=url,
                        )
                    )

        return findings

    async def _options_probe(self, client: httpx.AsyncClient, url: str) -> List[str]:
        """Send OPTIONS request and parse the Allow header."""
        try:
            resp = await client.options(url, headers=evasion.headers(include_referer=False))
            allow = resp.headers.get("Allow", resp.headers.get("allow", ""))
            return [m.strip().upper() for m in allow.split(",") if m.strip()]
        except httpx.RequestError:
            return []

    async def _probe_method(
        self, client: httpx.AsyncClient, url: str, method: str
    ) -> bool:
        """Return True if the server responds with anything other than 405."""
        try:
            resp = await client.request(method, url, headers=evasion.headers(include_referer=False))
            if resp.status_code == 405:
                return False
            logger.debug("Method %s on %s → HTTP %d", method, url, resp.status_code)
            return True
        except httpx.RequestError:
            return False
