"""
Rate-limiting middleware.

Uses an in-memory sliding-window counter (sufficient for a single process).
For multi-process deployments, swap the in-memory store for Redis.
"""
import time
from collections import defaultdict, deque
from typing import Callable, Deque

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from backend.config import settings
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Sliding-window rate limiter keyed on client IP address.

    Limits: RATE_LIMIT_REQUESTS per RATE_LIMIT_PERIOD seconds (from config).
    Excluded paths: /docs, /openapi.json, /health
    """

    EXCLUDED_PATHS = {
        "/docs", "/redoc", "/openapi.json",
        "/health", "/health/full",  # both health probes excluded
        "/metrics",                 # Prometheus scrape
        "/",
    }

    def __init__(self, app, requests: int = None, period: int = None):
        super().__init__(app)
        self.max_requests = requests or settings.RATE_LIMIT_REQUESTS
        self.period = period or settings.RATE_LIMIT_PERIOD
        # client_ip → deque of request timestamps
        self._windows: dict[str, Deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        now = time.monotonic()
        window = self._windows[client_ip]

        # Evict timestamps older than the window
        cutoff = now - self.period
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.max_requests:
            retry_after = int(self.period - (now - window[0])) + 1
            logger.warning("Rate limit exceeded for %s", client_ip)
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "detail": f"Rate limit: {self.max_requests} requests per {self.period}s",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        window.append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(self.max_requests - len(window))
        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        # Only honour X-Forwarded-For when explicitly trusted via config.
        # Default (False) avoids trivial rate-limit bypass via header spoofing.
        if settings.TRUST_PROXY_HEADERS:
            forwarded = request.headers.get("X-Forwarded-For")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
