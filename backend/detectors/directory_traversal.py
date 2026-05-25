"""
Directory Traversal Detector.

Probes common path traversal sequences to detect whether the application
leaks filesystem content outside the web root.
"""
import asyncio
from typing import List

import httpx

from backend.adaptive_scanner.adaptive_engine import evasion
from backend.detectors.base import Severity, VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)

_TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2Fetc%2Fpasswd",
    "..%252Fetc%252Fpasswd",
    "%2e%2e%2fetc%2fpasswd",
    "..\\windows\\system32\\drivers\\etc\\hosts",
    "..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
]

_UNIX_INDICATORS = ["root:x:", "daemon:", "/bin/bash", "/bin/sh"]
_WIN_INDICATORS  = ["[fonts]", "[extensions]", "localhost"]

_PATH_PARAMS = ["file", "path", "page", "doc", "filename", "template", "load", "include"]


class DirectoryTraversalDetector:
    """Test file-path parameters for directory traversal vulnerabilities."""

    REQUEST_TIMEOUT = 6.0

    async def detect(self, base_url: str) -> List[VulnerabilityFinding]:
        """Probe *base_url* for path traversal."""
        findings: List[VulnerabilityFinding] = []
        async with httpx.AsyncClient(
            timeout=self.REQUEST_TIMEOUT, verify=False, follow_redirects=True
        ) as client:
            for param in _PATH_PARAMS:
                for payload in _TRAVERSAL_PAYLOADS:
                    finding = await self._probe(client, base_url, param, payload)
                    if finding:
                        findings.append(finding)
                        break   # one finding per parameter is sufficient
        return findings

    async def _probe(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        param: str,
        payload: str,
    ) -> "VulnerabilityFinding | None":
        try:
            url = f"{base_url}?{param}={payload}"
            resp = await client.get(url, headers=evasion.headers())
            body = resp.text

            for indicator in _UNIX_INDICATORS + _WIN_INDICATORS:
                if indicator in body:
                    logger.warning(
                        "Directory traversal confirmed: param='%s' payload='%s' indicator='%s'",
                        param, payload, indicator,
                    )
                    return VulnerabilityFinding(
                        name="Directory Traversal / Path Traversal",
                        vuln_type="Directory Traversal",
                        severity=Severity.HIGH,
                        explanation=(
                            "The application allows directory traversal via the "
                            f"'{param}' parameter, leaking sensitive system files."
                        ),
                        technical_description=(
                            f"Payload '{payload}' in parameter '{param}' caused the "
                            f"response to include filesystem content ('{indicator}')."
                        ),
                        impact=(
                            "Attackers can read arbitrary files from the server filesystem, "
                            "including configuration files, credentials, and source code."
                        ),
                        fix=[
                            "Validate file paths against an allowlist of permitted values.",
                            "Use realpath() / canonical path normalisation and verify it starts with the web root.",
                            "Avoid passing user input directly to file-system APIs.",
                            "Run the web application under a chroot / containerised environment.",
                        ],
                        owasp_mapping="A01:2021 – Broken Access Control",
                        cve_references=["CVE-2021-41773", "CVE-2021-42013"],
                        cvss_score=7.5,
                        affected_url=url,
                        payload_used=payload,
                        response_snippet=body[:300],
                    )
        except httpx.RequestError as exc:
            logger.debug("Request error during traversal test %s: %s", base_url, exc)
        return None
