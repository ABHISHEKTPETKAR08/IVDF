"""
SSL/TLS Configuration Checker.

Identifies weak cipher suites, outdated protocol versions, certificate
issues, and other TLS misconfigurations.
"""
import asyncio
import ssl
import socket
from datetime import datetime, timezone
from typing import List

from backend.detectors.base import Severity, VulnerabilityFinding
from backend.utils.logger import get_logger

logger = get_logger(__name__)

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_CIPHERS_KEYWORDS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "MD5", "ADH", "AECDH"
]


class SSLChecker:
    """Analyse TLS configuration of an HTTPS endpoint."""

    CONNECT_TIMEOUT = 5.0

    async def detect(self, host: str, port: int = 443) -> List[VulnerabilityFinding]:
        """Connect to *host*:*port* and return TLS-related findings."""
        findings: List[VulnerabilityFinding] = []

        # asyncio.to_thread (Py 3.9+) is the idiomatic replacement for
        # get_event_loop().run_in_executor() with a None executor.
        cert_info = await asyncio.to_thread(self._get_cert_info, host, port)
        if not cert_info:
            return findings

        findings.extend(self._check_expiry(cert_info, host))
        findings.extend(self._check_protocol(cert_info, host))
        findings.extend(self._check_cipher(cert_info, host))
        findings.extend(self._check_self_signed(cert_info, host))

        return findings

    # ── Certificate retrieval ─────────────────────────────────────────────────

    def _get_cert_info(self, host: str, port: int) -> dict:
        """Synchronous TLS handshake to retrieve certificate and cipher info."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Allow legacy protocols for detection purposes
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

            with socket.create_connection((host, port), timeout=self.CONNECT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    return {
                        "cert": cert,
                        "cipher_name": cipher[0] if cipher else "",
                        "cipher_bits": cipher[2] if cipher else 0,
                        "protocol": protocol or "",
                    }
        except Exception as exc:
            logger.debug("SSL info retrieval failed for %s:%d — %s", host, port, exc)
            return {}

    # ── Individual checks ─────────────────────────────────────────────────────

    def _check_expiry(self, info: dict, host: str) -> List[VulnerabilityFinding]:
        findings = []
        cert = info.get("cert", {})
        not_after = cert.get("notAfter")
        if not not_after:
            return findings

        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            now = datetime.now(tz=timezone.utc)
            days_left = (expiry - now).days

            if days_left < 0:
                findings.append(
                    VulnerabilityFinding(
                        name="Expired TLS Certificate",
                        vuln_type="Weak SSL/TLS Configuration",
                        severity=Severity.CRITICAL,
                        explanation="The TLS certificate has expired.",
                        technical_description=f"Certificate expired on {not_after}.",
                        impact="Browsers will reject the connection; MITM attacks may go unnoticed.",
                        fix=["Renew the TLS certificate immediately.", "Use Let's Encrypt for automatic renewal."],
                        owasp_mapping="A02:2021 – Cryptographic Failures",
                        cvss_score=9.1,
                        affected_url=f"https://{host}",
                    )
                )
            elif days_left < 30:
                findings.append(
                    VulnerabilityFinding(
                        name="TLS Certificate Expiring Soon",
                        vuln_type="Weak SSL/TLS Configuration",
                        severity=Severity.MEDIUM,
                        explanation=f"The TLS certificate expires in {days_left} days.",
                        technical_description=f"Certificate expiry: {not_after}.",
                        impact="Service disruption when certificate expires.",
                        fix=["Renew the certificate before expiry.", "Automate renewal with Certbot / ACME."],
                        owasp_mapping="A02:2021 – Cryptographic Failures",
                        cvss_score=5.0,
                        affected_url=f"https://{host}",
                    )
                )
        except ValueError:
            pass

        return findings

    def _check_protocol(self, info: dict, host: str) -> List[VulnerabilityFinding]:
        findings = []
        proto = info.get("protocol", "")
        if any(weak in proto for weak in _WEAK_PROTOCOLS):
            findings.append(
                VulnerabilityFinding(
                    name=f"Weak TLS Protocol: {proto}",
                    vuln_type="Weak SSL/TLS Configuration",
                    severity=Severity.HIGH,
                    explanation=f"The server negotiated {proto}, which has known vulnerabilities.",
                    technical_description=f"Deprecated protocol {proto} accepted during handshake.",
                    impact="Susceptible to POODLE, BEAST, DROWN and downgrade attacks.",
                    fix=[
                        "Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1.",
                        "Configure server to support only TLSv1.2 and TLSv1.3.",
                        "Use modern cipher suites with Perfect Forward Secrecy.",
                    ],
                    owasp_mapping="A02:2021 – Cryptographic Failures",
                    cvss_score=7.5,
                    affected_url=f"https://{host}",
                )
            )
        return findings

    def _check_cipher(self, info: dict, host: str) -> List[VulnerabilityFinding]:
        findings = []
        cipher = info.get("cipher_name", "")
        bits = info.get("cipher_bits", 128)
        if any(kw in cipher.upper() for kw in _WEAK_CIPHERS_KEYWORDS) or bits < 128:
            findings.append(
                VulnerabilityFinding(
                    name=f"Weak TLS Cipher Suite: {cipher}",
                    vuln_type="Weak SSL/TLS Configuration",
                    severity=Severity.HIGH,
                    explanation=f"The negotiated cipher '{cipher}' ({bits}-bit) is considered weak.",
                    technical_description=f"Cipher: {cipher}, key size: {bits} bits.",
                    impact="Encrypted traffic may be decrypted offline by adversaries.",
                    fix=[
                        "Disable RC4, DES, 3DES, EXPORT, and NULL cipher suites.",
                        "Prefer AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
                        "Use Mozilla SSL Configuration Generator for recommended cipher lists.",
                    ],
                    owasp_mapping="A02:2021 – Cryptographic Failures",
                    cvss_score=7.0,
                    affected_url=f"https://{host}",
                )
            )
        return findings

    def _check_self_signed(self, info: dict, host: str) -> List[VulnerabilityFinding]:
        findings = []
        cert = info.get("cert", {})
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        if subject == issuer:
            findings.append(
                VulnerabilityFinding(
                    name="Self-Signed TLS Certificate",
                    vuln_type="Weak SSL/TLS Configuration",
                    severity=Severity.MEDIUM,
                    explanation="The certificate is self-signed and not trusted by browsers.",
                    technical_description="Subject and issuer fields in the certificate are identical.",
                    impact="Users receive browser warnings; vulnerable to MITM if accepted.",
                    fix=[
                        "Obtain a certificate from a trusted CA (e.g., Let's Encrypt).",
                        "Self-signed certs are acceptable only in isolated lab environments.",
                    ],
                    owasp_mapping="A02:2021 – Cryptographic Failures",
                    cvss_score=5.9,
                    affected_url=f"https://{host}",
                )
            )
        return findings
