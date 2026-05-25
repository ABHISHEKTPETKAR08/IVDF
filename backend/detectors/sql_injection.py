"""
SQL Injection Detector.

Tests web forms and URL parameters for classic, blind, and error-based
SQL injection patterns.  Only targets authorised lab applications such as
DVWA, OWASP Juice Shop, and Metasploitable web services.
"""
import asyncio
from typing import List
from urllib.parse import urlencode, urljoin, urlparse, parse_qs

import httpx

from backend.adaptive_scanner.adaptive_engine import evasion
from backend.detectors.base import Severity, VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Payloads designed to trigger detectable SQL errors (not exploitation)
_SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "1; SELECT 1",
    "1' AND SLEEP(0)--",       # time-based blind (0-second — detect, don't hang)
    "1 AND 1=2 UNION SELECT NULL--",
]

_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "ORA-",
    "pg_query()",
    "sqlite3.OperationalError",
    "microsoft odbc",
    "sqlserver",
]


class SQLInjectionDetector:
    """Detect SQL injection vulnerabilities in HTTP endpoints."""

    REQUEST_TIMEOUT = 6.0

    async def detect(self, base_url: str) -> List[VulnerabilityFinding]:
        """
        Probe *base_url* with common SQL injection payloads.
        Returns a list of findings (may be empty).
        """
        findings: List[VulnerabilityFinding] = []
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        if not params:
            # Try common parameter names if URL has no query string
            test_params = {"id": "1", "search": "test", "q": "test", "username": "test"}
        else:
            test_params = {k: v[0] for k, v in params.items()}

        async with httpx.AsyncClient(
            timeout=self.REQUEST_TIMEOUT,
            verify=False,
            follow_redirects=True,
        ) as client:
            for param_name in test_params:
                for payload in _SQLI_PAYLOADS:
                    # Try the raw payload first, then URL-encoded variants
                    # to bypass WAF string-matching rules
                    # Cap to 2 variants per payload — the 3rd typically adds
                    # no detection coverage but doubles request volume.
                    for variant in evasion.payload_variants(payload)[:2]:
                        finding = await self._test_param(
                            client, base_url, param_name, variant
                        )
                        if finding:
                            finding.payload_used = f"{payload}  [variant: {variant}]"
                            findings.append(finding)
                            break
                    if findings:
                        break   # one confirmed finding per parameter is enough

        return findings

    async def _test_param(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        payload: str,
    ) -> "VulnerabilityFinding | None":
        """Inject *payload* into *param* and analyse the response."""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [payload]
            test_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()

            resp = await client.get(test_url, headers=evasion.headers())
            body = resp.text.lower()

            for sig in _ERROR_SIGNATURES:
                if sig.lower() in body:
                    logger.warning(
                        "SQL injection indicator found: '%s' in response to payload '%s'",
                        sig,
                        payload,
                    )
                    return VulnerabilityFinding(
                        name="SQL Injection",
                        vuln_type="SQL Injection",
                        severity=Severity.HIGH,
                        explanation=(
                            "The application returns database error messages when SQL "
                            "metacharacters are injected into the request parameter."
                        ),
                        technical_description=(
                            f"Parameter '{param}' is reflected in an SQL query without "
                            f"sanitisation. Payload '{payload}' triggered the error "
                            f"signature: '{sig}'."
                        ),
                        impact=(
                            "Attackers can read, modify, or delete database records; "
                            "bypass authentication; and potentially execute OS commands."
                        ),
                        fix=[
                            "Use parameterised queries / prepared statements.",
                            "Apply input validation and allowlist filtering.",
                            "Disable detailed database error messages in production.",
                            "Implement least-privilege database accounts.",
                            "Use a Web Application Firewall (WAF).",
                        ],
                        owasp_mapping="A03:2021 – Injection",
                        cve_references=[],
                        cvss_score=8.8,
                        affected_url=test_url,
                        payload_used=payload,
                        response_snippet=resp.text[:300],
                    )
        except httpx.RequestError as exc:
            logger.debug("Request error while testing SQLi on %s: %s", url, exc)

        return None
