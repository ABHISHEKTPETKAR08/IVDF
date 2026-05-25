"""
Input validation utilities.

Validates that scan targets are syntactically correct IP addresses, hostnames,
or URLs. Policy enforcement (ensuring authorisation to scan) is the operator's
responsibility — this tool is designed for authorised security assessments only.
"""
import ipaddress
import re
import socket
from typing import Tuple
from urllib.parse import urlparse

from backend.utils.logger import get_logger

logger = get_logger(__name__)

# RFC-1123 hostname pattern
_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_private_ip(ip_str: str) -> bool:
    """Return True when the IP belongs to a private/loopback range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def resolve_host(host: str) -> str:
    """Resolve hostname to IP; raise ValueError on failure."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve host '{host}': {exc}") from exc


def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate a scan target (IP, hostname, or URL).

    Accepts any syntactically valid target — private or public.
    Logs a warning for public IPs to remind the operator to have
    written authorisation before scanning.

    Returns (is_valid, reason).
    """
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string."

    target = target.strip()

    # Remove URL fragment (#...) before parsing — fragments are client-side only
    if "#" in target:
        target = target.split("#", 1)[0]

    # URL form — extract the hostname
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        host = parsed.hostname or ""
        if not host:
            return False, "URL contains no hostname."
        return _validate_host_format(host)

    # Strip port for bare host:port notation (IPv4 / hostnames only)
    host = target
    if ":" in target and not target.startswith("["):
        host = target.rsplit(":", 1)[0]

    return _validate_host_format(host)


def _validate_host_format(host: str) -> Tuple[bool, str]:
    """Accept any syntactically valid IPv4, IPv6, or RFC-1123 hostname."""
    host = host.strip().strip("[]")  # strip IPv6 brackets
    if not host:
        return False, "Empty host."

    # IPv4 / IPv6 address?
    try:
        ip = ipaddress.ip_address(host)
        if not is_private_ip(str(ip)):
            logger.warning(
                "Public IP target '%s' — ensure written authorisation before scanning.", host
            )
        return True, "ok"
    except ValueError:
        pass

    # RFC-1123 hostname? — note we deliberately do NOT perform DNS resolution
    # here. Doing so would block the event loop on every incoming request and
    # opens a DNS-amplification DoS surface. Resolution is the recon phase's
    # responsibility (executed off-thread).
    if _HOSTNAME_RE.match(host):
        return True, "ok"

    return False, f"'{host}' is not a valid IP address or hostname."


def validate_port_range(port_range: str) -> Tuple[bool, str]:
    """Validate a port-range string like '1-1024' or '80,443,8080'."""
    try:
        if "-" in port_range:
            start, end = port_range.split("-", 1)
            s, e = int(start.strip()), int(end.strip())
            if not (1 <= s <= 65535 and 1 <= e <= 65535 and s <= e):
                raise ValueError
        else:
            for p in port_range.split(","):
                v = int(p.strip())
                if not 1 <= v <= 65535:
                    raise ValueError
        return True, "ok"
    except (ValueError, TypeError):
        return False, f"Invalid port range: '{port_range}'. Use 'start-end' or 'p1,p2,…'."


def sanitize_string(value: str, max_length: int = 256) -> str:
    """Strip dangerous characters and truncate."""
    cleaned = re.sub(r"[<>\"';\\]", "", value)
    return cleaned[:max_length]
