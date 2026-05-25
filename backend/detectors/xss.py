"""
Cross-Site Scripting (XSS) Detector.

Sends harmless, non-executing probe strings to identify reflected XSS sinks.
No actual JavaScript execution or session-stealing is attempted.
"""
import asyncio
from typing import List
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from backend.adaptive_scanner.adaptive_engine import evasion
from backend.detectors.base import Severity, VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Probe markers that reveal reflection WITHOUT executing code
_XSS_PROBES = [
    "<xss-test-{n}>",
    '"><xss-test-{n}>',
    "'><xss-test-{n}>",
    "</title><xss-test-{n}>",
    "javascript:xsstest{n}",
]

_SCRIPT_SINK_PATTERNS = [
    "<script",
    "onerror=",
    "onload=",
    "javascript:",
    "<img ",
    "<svg ",
    "<iframe ",
]


class XSSDetector:
    """Detect reflected XSS vulnerabilities in HTTP GET parameters."""

    REQUEST_TIMEOUT = 6.0

    async def detect(self, base_url: str) -> List[VulnerabilityFinding]:
        """Probe *base_url* parameters for XSS reflection."""
        findings: List[VulnerabilityFinding] = []
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)

        if not params:
            test_params = {"search": "test", "q": "test", "input": "test", "name": "test"}
        else:
            test_params = {k: v[0] for k, v in params.items()}

        async with httpx.AsyncClient(
            timeout=self.REQUEST_TIMEOUT,
            verify=False,
            follow_redirects=True,
        ) as client:
            for idx, (param_name, _) in enumerate(test_params.items()):
                for probe_tpl in _XSS_PROBES:
                    probe = probe_tpl.format(n=idx)
                    finding = await self._test_reflection(
                        client, base_url, param_name, probe
                    )
                    if finding:
                        findings.append(finding)
                        break

        return findings

    async def _test_reflection(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        probe: str,
    ) -> "VulnerabilityFinding | None":
        """Inject *probe* and check whether it is reflected unencoded."""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [probe]
            test_url = parsed._replace(query=urlencode(query, doseq=True)).geturl()

            resp = await client.get(test_url, headers=evasion.headers())
            body = resp.text

            if probe in body:
                # Unencoded reflection confirmed
                logger.warning(
                    "XSS probe reflected unencoded: param='%s' probe='%s'",
                    param,
                    probe,
                )
                return VulnerabilityFinding(
                    name="Reflected Cross-Site Scripting (XSS)",
                    vuln_type="XSS",
                    severity=Severity.HIGH,
                    explanation=(
                        "User-supplied input is reflected back into the HTML response "
                        "without encoding, enabling script injection."
                    ),
                    technical_description=(
                        f"Parameter '{param}' is echoed verbatim into the response body. "
                        f"Probe '{probe}' appeared unencoded in the HTML."
                    ),
                    impact=(
                        "Attackers can inject arbitrary JavaScript that runs in victims' "
                        "browsers, enabling session hijacking, credential theft, and "
                        "DOM manipulation."
                    ),
                    fix=[
                        "HTML-encode all user-supplied output (use templating engines with auto-escaping).",
                        "Implement a strict Content Security Policy (CSP).",
                        "Use the X-XSS-Protection and X-Content-Type-Options headers.",
                        "Validate and sanitise input server-side.",
                        "Avoid inserting raw user data into script contexts.",
                    ],
                    owasp_mapping="A03:2021 – Injection (XSS)",
                    cve_references=[],
                    cvss_score=7.4,
                    affected_url=test_url,
                    payload_used=probe,
                    response_snippet=body[:300],
                )
        except httpx.RequestError as exc:
            logger.debug("Request error while testing XSS on %s: %s", url, exc)

        return None
