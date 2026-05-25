"""
Nmap binary detection and validation.

Called once at application startup to surface a clear warning when nmap is
absent. The port scanner automatically falls back to pure-Python asyncio TCP
scanning, so the application still works — nmap is optional but recommended.
"""
import shutil
import subprocess
from typing import Optional, Tuple

from backend.utils.logger import get_logger

logger = get_logger(__name__)

_WINDOWS_SEARCH_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Nmap\nmap.exe",
]


def find_nmap() -> Optional[str]:
    """Return the full path to the nmap binary, or None if not found."""
    # 1. Check PATH first (covers winget/homebrew/apt installs)
    path = shutil.which("nmap")
    if path:
        return path

    # 2. Windows default install locations
    import os
    for candidate in _WINDOWS_SEARCH_PATHS:
        if os.path.isfile(candidate):
            return candidate

    return None


def get_nmap_version(nmap_path: str) -> Optional[str]:
    """Return 'Nmap 7.95' style version string, or None on failure."""
    try:
        out = subprocess.check_output(
            [nmap_path, "--version"],
            stderr=subprocess.STDOUT,
            timeout=5,
        ).decode("utf-8", errors="replace")
        first_line = out.strip().splitlines()[0]  # "Nmap version 7.95 ( https://nmap.org )"
        return first_line
    except Exception:
        return None


def check_nmap() -> Tuple[bool, str]:
    """
    Validate nmap availability.

    Returns:
        (True, version_string)   — nmap found and working
        (False, error_message)   — nmap absent or broken
    """
    path = find_nmap()
    if not path:
        msg = (
            "nmap binary not found. Port scanning will use the pure-Python "
            "asyncio TCP fallback (no OS fingerprinting or service version detection). "
            "Install nmap: https://nmap.org/download.html  "
            "or run: winget install --id Insecure.Nmap"
        )
        return False, msg

    version = get_nmap_version(path)
    if not version:
        msg = f"nmap found at {path!r} but could not be executed."
        return False, msg

    return True, f"{version} @ {path}"


def verify_python_nmap(nmap_path: str) -> bool:
    """Check that python-nmap can find and use the nmap binary."""
    try:
        import nmap  # type: ignore
        nm = nmap.PortScanner()
        # PortScanner() raises nmap.PortScannerError if binary not found
        return True
    except Exception:
        return False


def log_nmap_status() -> bool:
    """
    Run nmap check and emit an appropriate log message.

    Called from the FastAPI lifespan on startup.
    Returns True if nmap is available.
    """
    available, detail = check_nmap()
    if available:
        logger.info("nmap available: %s", detail)
        python_nmap_ok = verify_python_nmap(find_nmap())
        if not python_nmap_ok:
            logger.warning(
                "python-nmap installed but cannot locate nmap binary. "
                "Ensure nmap is on PATH or set nmap_path explicitly."
            )
    else:
        logger.warning("nmap unavailable — %s", detail)
    return available
