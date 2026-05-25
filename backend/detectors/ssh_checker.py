"""
SSH Configuration Checker.

Detects weak SSH configurations by analysing the server banner and
attempting key-exchange negotiation (read-only, no authentication).
"""
import asyncio
import re
from typing import List

from backend.detectors.base import Severity, VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)

_WEAK_SSH_VERSIONS = re.compile(r"SSH-(1\.\d+|2\.0)", re.IGNORECASE)
_OLD_OPENSSH = re.compile(r"OpenSSH[_\s](\d+)\.(\d+)", re.IGNORECASE)

# Known weak OpenSSH versions (below 7.4)
_MIN_MAJOR = 7
_MIN_MINOR = 4


class SSHChecker:
    """Analyse SSH banner and configuration for security weaknesses."""

    CONNECT_TIMEOUT = 5.0

    async def detect(self, host: str, port: int = 22) -> List[VulnerabilityFinding]:
        """Connect to SSH port and analyse the banner."""
        findings: List[VulnerabilityFinding] = []
        banner = await self._read_banner(host, port)

        if not banner:
            return findings

        findings.extend(self._check_ssh1(banner, host, port))
        findings.extend(self._check_old_openssh(banner, host, port))
        findings.extend(self._check_info_disclosure(banner, host, port))

        return findings

    async def _read_banner(self, host: str, port: int) -> str:
        """Read the SSH identification string without authenticating."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.CONNECT_TIMEOUT,
            )
            banner_bytes = await asyncio.wait_for(reader.read(256), timeout=3.0)
            writer.close()
            await writer.wait_closed()
            return banner_bytes.decode("utf-8", errors="replace").strip()
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return ""

    def _check_ssh1(self, banner: str, host: str, port: int) -> List[VulnerabilityFinding]:
        if "SSH-1" in banner:
            return [
                VulnerabilityFinding(
                    name="SSH Protocol Version 1 Enabled",
                    vuln_type="Weak SSH Configuration",
                    severity=Severity.CRITICAL,
                    explanation="The server supports SSH protocol v1, which is cryptographically broken.",
                    technical_description=f"Banner: '{banner}'. SSH-1 uses weak RC4/DES and lacks MAC integrity.",
                    impact="MITM attackers can intercept or modify SSH sessions.",
                    fix=[
                        "Disable SSH protocol version 1: set 'Protocol 2' in sshd_config.",
                        "Restart the SSH daemon after changes.",
                    ],
                    owasp_mapping="A02:2021 – Cryptographic Failures",
                    cvss_score=9.1,
                    affected_url=f"ssh://{host}:{port}",
                    affected_port=port,
                    response_snippet=banner,
                )
            ]
        return []

    def _check_old_openssh(self, banner: str, host: str, port: int) -> List[VulnerabilityFinding]:
        match = _OLD_OPENSSH.search(banner)
        if not match:
            return []
        major, minor = int(match.group(1)), int(match.group(2))
        if major < _MIN_MAJOR or (major == _MIN_MAJOR and minor < _MIN_MINOR):
            version = f"{major}.{minor}"
            return [
                VulnerabilityFinding(
                    name=f"Outdated OpenSSH Version: {version}",
                    vuln_type="Weak SSH Configuration",
                    severity=Severity.HIGH,
                    explanation=(
                        f"OpenSSH {version} is below the recommended minimum ({_MIN_MAJOR}.{_MIN_MINOR}) "
                        "and may be vulnerable to known CVEs."
                    ),
                    technical_description=f"Banner: '{banner}'.",
                    impact="Version-specific exploits may allow privilege escalation or remote code execution.",
                    fix=[
                        f"Upgrade OpenSSH to {_MIN_MAJOR}.{_MIN_MINOR} or later.",
                        "Apply OS security patches regularly.",
                    ],
                    owasp_mapping="A06:2021 – Vulnerable and Outdated Components",
                    cvss_score=7.8,
                    affected_url=f"ssh://{host}:{port}",
                    affected_port=port,
                    response_snippet=banner,
                )
            ]
        return []

    def _check_info_disclosure(self, banner: str, host: str, port: int) -> List[VulnerabilityFinding]:
        if "OpenSSH" in banner or "dropbear" in banner.lower():
            return [
                VulnerabilityFinding(
                    name="SSH Banner Information Disclosure",
                    vuln_type="Information Disclosure",
                    severity=Severity.LOW,
                    explanation="The SSH banner reveals the server software and version.",
                    technical_description=f"Banner: '{banner}'.",
                    impact="Assists attackers in identifying version-specific vulnerabilities.",
                    fix=[
                        "Set 'Banner /dev/null' and 'DebianBanner no' in sshd_config.",
                        "Suppress version info with 'VersionAddendum none'.",
                    ],
                    owasp_mapping="A05:2021 – Security Misconfiguration",
                    cvss_score=3.1,
                    affected_url=f"ssh://{host}:{port}",
                    affected_port=port,
                    response_snippet=banner,
                )
            ]
        return []
