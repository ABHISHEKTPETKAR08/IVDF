"""
Prometheus metrics — exposed at /metrics.

We avoid an `import prometheus_client` hard dependency: if the package is
absent (e.g., minimal dev install), the module falls back to a no-op shim so
the rest of the backend keeps working.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator, Optional

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Histogram,
        Gauge,
        generate_latest,
    )
    AVAILABLE = True
except ImportError:  # graceful degradation
    AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain"

    class _Noop:
        def __init__(self, *a, **kw): pass
        def labels(self, *a, **kw): return self
        def inc(self, *a, **kw): pass
        def dec(self, *a, **kw): pass
        def set(self, *a, **kw): pass
        def observe(self, *a, **kw): pass

    Counter = Histogram = Gauge = _Noop  # type: ignore

    def generate_latest():  # type: ignore
        return b"# prometheus_client not installed\n"


# ── Metric definitions ────────────────────────────────────────────────────────

HTTP_REQUESTS = Counter(
    "ivdaf_http_requests_total",
    "HTTP requests handled by the API.",
    ["method", "path", "status"],
)

HTTP_LATENCY = Histogram(
    "ivdaf_http_request_duration_seconds",
    "End-to-end request handling latency.",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)

SCANS_STARTED = Counter(
    "ivdaf_scans_started_total",
    "Scans accepted by /scan.",
    ["scan_type", "execution_path"],
)

SCANS_COMPLETED = Counter(
    "ivdaf_scans_completed_total",
    "Scans that finished (any terminal state).",
    ["scan_type", "status"],
)

SCAN_DURATION = Histogram(
    "ivdaf_scan_duration_seconds",
    "Wall-clock duration of completed scans.",
    ["scan_type"],
    buckets=(1, 5, 10, 30, 60, 120, 300, 600, 1200),
)

ACTIVE_SCANS = Gauge(
    "ivdaf_active_scans",
    "Scans currently in RUNNING state.",
)

DETECTOR_FINDINGS = Counter(
    "ivdaf_detector_findings_total",
    "Findings produced, labelled by vulnerability type and severity.",
    ["vuln_type", "severity"],
)


@contextmanager
def time_block(metric: Histogram, *labels: str) -> Iterator[None]:
    """Convenience: `with time_block(SCAN_DURATION, scan_type): ...`."""
    t0 = time.perf_counter()
    try:
        yield
    finally:
        if labels:
            metric.labels(*labels).observe(time.perf_counter() - t0)
        else:
            metric.observe(time.perf_counter() - t0)


def render() -> bytes:
    """Render the metrics in Prometheus exposition format."""
    return generate_latest()
