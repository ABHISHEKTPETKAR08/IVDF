"""
Reconnaissance module.

Performs passive and active information-gathering against a target:
  - DNS resolution
  - Reverse DNS lookup
  - WHOIS (via python-whois)
  - Banner grabbing (TCP socket)
  - OS / service detection hints

All network interactions are performed only against explicitly authorised
lab targets (DVWA, OWASP Juice Shop, Metasploitable).
"""
import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# Optional heavy imports — gracefully degrade if library not installed
try:
    import whois as python_whois  # type: ignore
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed; WHOIS lookups disabled.")


@dataclass
class ReconResult:
    """Aggregated reconnaissance data for one target."""
    target: str
    resolved_ip: Optional[str] = None
    reverse_dns: Optional[str] = None
    whois_info: Dict = field(default_factory=dict)
    open_banners: Dict[int, str] = field(default_factory=dict)  # port → banner
    detected_services: Dict[int, str] = field(default_factory=dict)
    ssl_info: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class ReconScanner:
    """Performs reconnaissance against a single target."""

    COMMON_PORTS: List[int] = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                                3306, 3389, 5432, 6379, 8080, 8443, 27017]

    BANNER_TIMEOUT: float = 3.0

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    # ── Public entry-point ────────────────────────────────────────────────────

    async def run(self, target: str) -> ReconResult:
        """Execute all recon tasks concurrently and return aggregated result."""
        result = ReconResult(target=target)

        # Resolve hostname → IP
        result.resolved_ip = await self._resolve(target, result)
        if not result.resolved_ip:
            return result

        # Run remaining tasks concurrently
        await asyncio.gather(
            self._reverse_dns(result),
            self._whois(target, result),
            self._grab_banners(result),
            self._ssl_info(target, result),
            return_exceptions=True,
        )

        return result

    # ── Individual tasks ──────────────────────────────────────────────────────

    async def _resolve(self, target: str, result: ReconResult) -> Optional[str]:
        """Resolve hostname to IP address."""
        loop = asyncio.get_running_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, target)
            logger.debug("Resolved %s → %s", target, ip)
            return ip
        except socket.gaierror as exc:
            msg = f"DNS resolution failed for {target}: {exc}"
            logger.warning(msg)
            result.errors.append(msg)
            return None

    async def _reverse_dns(self, result: ReconResult) -> None:
        """Perform reverse DNS lookup on the resolved IP."""
        loop = asyncio.get_running_loop()
        try:
            hostname, *_ = await loop.run_in_executor(
                None, socket.gethostbyaddr, result.resolved_ip
            )
            result.reverse_dns = hostname
        except (socket.herror, socket.gaierror):
            result.reverse_dns = None

    async def _whois(self, target: str, result: ReconResult) -> None:
        """Fetch WHOIS information for the target domain / IP."""
        if not _WHOIS_AVAILABLE:
            result.whois_info = {"error": "python-whois not installed"}
            return
        loop = asyncio.get_running_loop()
        try:
            raw = await loop.run_in_executor(None, python_whois.whois, target)
            result.whois_info = {
                "registrar": getattr(raw, "registrar", None),
                "creation_date": str(getattr(raw, "creation_date", None)),
                "expiration_date": str(getattr(raw, "expiration_date", None)),
                "name_servers": getattr(raw, "name_servers", []),
                "org": getattr(raw, "org", None),
                "country": getattr(raw, "country", None),
            }
        except Exception as exc:
            result.whois_info = {"error": str(exc)}

    async def _grab_banners(self, result: ReconResult) -> None:
        """Grab service banners from common ports."""
        tasks = [
            self._grab_single_banner(result.resolved_ip, port, result)
            for port in self.COMMON_PORTS
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _grab_single_banner(
        self, ip: str, port: int, result: ReconResult
    ) -> None:
        """Connect to one port and read the first 1024 bytes."""
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.BANNER_TIMEOUT)
            try:
                # Send a generic HTTP probe for web ports; otherwise just read
                if port in (80, 8080, 8443, 443):
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                banner_bytes = await asyncio.wait_for(
                    reader.read(1024), timeout=self.BANNER_TIMEOUT
                )
                banner = banner_bytes.decode("utf-8", errors="replace").strip()
                if banner:
                    result.open_banners[port] = banner[:512]
                    result.detected_services[port] = self._guess_service(port, banner)
            finally:
                writer.close()
                await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            pass  # Port closed or filtered — expected

    def _guess_service(self, port: int, banner: str) -> str:
        """Heuristic service identification from port number and banner text."""
        _map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
            6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
        }
        svc = _map.get(port, "Unknown")
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            svc = "SSH"
        elif "ftp" in banner_lower:
            svc = "FTP"
        elif "smtp" in banner_lower:
            svc = "SMTP"
        elif "http" in banner_lower:
            svc = "HTTP"
        return svc

    async def _ssl_info(self, target: str, result: ReconResult) -> None:
        """Collect TLS certificate metadata from port 443."""
        loop = asyncio.get_running_loop()
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = await asyncio.wait_for(
                asyncio.open_connection(target, 443, ssl=ctx), timeout=self.BANNER_TIMEOUT
            )
            reader, writer = conn
            try:
                cert = writer.get_extra_info("ssl_object").getpeercert()
                result.ssl_info = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName", []),
                }
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as exc:
            result.ssl_info = {"error": str(exc)}
