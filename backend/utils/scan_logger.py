"""
Per-scan structured-context logger.

Wrap any logger with `scan_logger(scan_id, target)` and every emitted line
carries `scan_id` + `target` fields. In JSON-log mode these are first-class
fields; in text mode they appear in the message prefix.

Usage:
    log = scan_logger(get_logger(__name__), scan_id=scan_id, target=target)
    log.info("Phase 2: Reconnaissance")   # -> ts | INFO | scan_id=xxx target=yy | Phase 2...
"""
from __future__ import annotations

import logging
from typing import Optional


class ScanLoggerAdapter(logging.LoggerAdapter):
    """Prepends `scan_id` and `target` to every log record."""

    def process(self, msg, kwargs):
        extra = self.extra or {}
        prefix = " ".join(f"{k}={v}" for k, v in extra.items() if v is not None)
        return (f"[{prefix}] {msg}" if prefix else msg), kwargs


def scan_logger(
    base: logging.Logger, *, scan_id: str, target: Optional[str] = None,
) -> logging.LoggerAdapter:
    """Return a LoggerAdapter that binds scan_id + target to every record."""
    return ScanLoggerAdapter(base, {"scan_id": scan_id[:8], "target": target})
