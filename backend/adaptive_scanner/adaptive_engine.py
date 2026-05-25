"""
Adaptive (low-noise) Scanning Engine.

Implements IDS/IPS/firewall-aware scanning for DEFENSIVE, EDUCATIONAL use only.
All techniques here reduce detection probability during authorised assessments —
they must NOT be used against systems without explicit written permission.

Adaptive behaviours implemented:
  - Randomised inter-probe delays (Poisson-distributed)
  - Exponential back-off on packet loss / RST storms
  - Dynamic rate throttling based on response latency
  - Jitter injection to avoid uniform timing signatures
  - Automatic slow-scan mode when anomalies are detected
  - User-agent rotation + browser-realistic headers (EvasionProfile)
  - URL-encoding payload variants to bypass WAF signature matching
  - Randomised port scan ordering to avoid sequential-scan detection
"""
import asyncio
import math
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional
from urllib.parse import quote

from backend.config import settings
from backend.utils.logger import get_logger

logger = get_logger(__name__)


# ── EvasionProfile ─────────────────────────────────────────────────────────────

_USER_AGENTS = [
    # Chrome — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox — Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari — macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Chrome — Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    # Safari — iOS
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
]

_ACCEPT_VALUES = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
]

_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,fr;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "es-ES,es;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en-US;q=0.8",
]

# Weighted towards None (most real requests have no Referer)
_REFERERS = [None, None, None, None,
             "https://www.google.com/",
             "https://www.bing.com/",
             "https://duckduckgo.com/",
             "https://search.yahoo.com/"]


class EvasionProfile:
    """
    Generates randomised HTTP headers and timing patterns to reduce
    IDS / IPS / WAF detection probability during authorised assessments.

    Techniques applied
    ------------------
    * User-agent rotation   — 8 real browser signatures (Chrome/FF/Safari/Edge)
    * Browser-realistic Accept / Accept-Language / Cache-Control headers
    * Sec-Fetch-* hints     — Chrome security fetch metadata headers
    * Poisson-distributed inter-request delays — evades uniform timing signatures
    * URL-encoding payload variants — bypass WAF regex / string-match rules
    * Randomised port scan order — defeats sequential-scan IDS rules
    """

    def headers(self, include_referer: bool = True) -> Dict[str, str]:
        """Return a browser-realistic HTTP header dict for a single request."""
        h: Dict[str, str] = {
            "User-Agent":               random.choice(_USER_AGENTS),
            "Accept":                   random.choice(_ACCEPT_VALUES),
            "Accept-Language":          random.choice(_ACCEPT_LANGUAGES),
            "Accept-Encoding":          "gzip, deflate, br",
            "Connection":               "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control":            "max-age=0",
            "Sec-Fetch-Dest":           "document",
            "Sec-Fetch-Mode":           "navigate",
            "Sec-Fetch-Site":           "none",
            "Sec-Fetch-User":           "?1",
            "DNT":                      "1",
        }
        if include_referer:
            ref = random.choice(_REFERERS)
            if ref:
                h["Referer"] = ref
        return h

    def poisson_delay(self, mean_seconds: float) -> float:
        """
        Sample a delay from an exponential distribution.

        Inter-arrival times of a Poisson process are exponentially distributed,
        making the request cadence indistinguishable from organic browsing
        rather than a regular scan interval.
        """
        return random.expovariate(1.0 / max(mean_seconds, 0.01))

    def payload_variants(self, payload: str) -> List[str]:
        """
        Return up to four encoding variants of *payload* to bypass WAF
        signature matching that relies on exact string patterns.

        Variants produced:
        - Original
        - Single URL-encode (e.g. ' → %27)
        - Double URL-encode (e.g. ' → %2527)
        - HTML entity form for < > quotes
        """
        variants: List[str] = [payload]

        enc1 = quote(payload, safe="")
        if enc1 != payload:
            variants.append(enc1)

        enc2 = quote(enc1, safe="")
        if enc2 not in variants:
            variants.append(enc2)

        # Hex-encode single quote specifically (common WAF bypass)
        hex_variant = payload.replace("'", "%27").replace('"', "%22").replace(" ", "%20")
        if hex_variant not in variants:
            variants.append(hex_variant)

        # Deduplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)
        return unique

    def randomize_port_order(self, ports: List[int]) -> List[int]:
        """Shuffle *ports* to avoid sequential port-scan IDS signatures."""
        shuffled = list(ports)
        random.shuffle(shuffled)
        return shuffled


# Module-level singleton — import this in detectors and scanners
evasion = EvasionProfile()


class ScanMode(str, Enum):
    AGGRESSIVE = "aggressive"   # Fast — only for isolated lab VMs
    NORMAL = "normal"           # Balanced
    STEALTH = "stealth"         # Slow / low-noise — mimics legitimate traffic
    ADAPTIVE = "adaptive"       # Self-tunes based on observed responses


@dataclass
class AdaptiveStats:
    """Runtime metrics used to tune scan behaviour."""
    probes_sent: int = 0
    probes_succeeded: int = 0
    probes_dropped: int = 0
    total_latency_ms: float = 0.0
    current_delay: float = settings.ADAPTIVE_SCAN_DELAY_MIN
    consecutive_drops: int = 0
    mode: ScanMode = ScanMode.ADAPTIVE

    @property
    def drop_rate(self) -> float:
        if self.probes_sent == 0:
            return 0.0
        return self.probes_dropped / self.probes_sent

    @property
    def avg_latency_ms(self) -> float:
        if self.probes_succeeded == 0:
            return 0.0
        return self.total_latency_ms / self.probes_succeeded


class AdaptiveScanEngine:
    """
    Wraps any async probe coroutine with adaptive timing and retry logic.

    Usage::

        engine = AdaptiveScanEngine(mode=ScanMode.ADAPTIVE)
        for target_item in items:
            result = await engine.probe(my_probe_fn, target_item)
    """

    # Thresholds that trigger escalation to a slower mode
    _DROP_RATE_THRESHOLD = 0.20      # >20 % drops → slow down
    _LATENCY_SPIKE_FACTOR = 3.0      # latency > 3× average → slow down
    _MAX_CONSECUTIVE_DROPS = 5

    def __init__(
        self,
        mode: ScanMode = ScanMode.ADAPTIVE,
        min_delay: float = settings.ADAPTIVE_SCAN_DELAY_MIN,
        max_delay: float = settings.ADAPTIVE_SCAN_DELAY_MAX,
        max_retries: int = settings.MAX_RETRIES,
    ):
        self.mode = mode
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.max_retries = max_retries
        self.stats = AdaptiveStats(mode=mode)

        # Fixed delays per mode (seconds)
        self._mode_delay: dict = {
            ScanMode.AGGRESSIVE: 0.0,
            ScanMode.NORMAL: 0.2,
            ScanMode.STEALTH: 2.0,
            ScanMode.ADAPTIVE: min_delay,
        }

    # ── Public API ────────────────────────────────────────────────────────────

    async def probe(
        self,
        coro_fn: Callable[..., Coroutine],
        *args: Any,
        **kwargs: Any,
    ) -> Optional[Any]:
        """
        Execute *coro_fn* with adaptive retry/delay logic.

        Returns the coroutine's result, or None if all retries exhausted.
        """
        for attempt in range(1, self.max_retries + 1):
            await self._pre_probe_delay()
            t0 = time.monotonic()

            try:
                result = await coro_fn(*args, **kwargs)
                elapsed_ms = (time.monotonic() - t0) * 1000
                self._record_success(elapsed_ms)
                return result

            except (asyncio.TimeoutError, OSError, ConnectionRefusedError) as exc:
                elapsed_ms = (time.monotonic() - t0) * 1000
                self._record_drop()
                logger.debug(
                    "Probe attempt %d/%d failed (%s). Drop-rate=%.1f%%",
                    attempt,
                    self.max_retries,
                    exc,
                    self.stats.drop_rate * 100,
                )

                if attempt < self.max_retries:
                    backoff = self._backoff_delay(attempt)
                    logger.debug("Back-off %.2fs before retry.", backoff)
                    await asyncio.sleep(backoff)

        return None

    async def batch_probe(
        self,
        coro_fn: Callable[..., Coroutine],
        items: List[Any],
        concurrency: int = 10,
    ) -> List[Optional[Any]]:
        """
        Run *coro_fn* over a list of *items* with adaptive concurrency control.

        Automatically lowers concurrency if the drop rate climbs.
        """
        effective_concurrency = self._effective_concurrency(concurrency)
        sem = asyncio.Semaphore(effective_concurrency)

        async def _guarded(item: Any) -> Optional[Any]:
            async with sem:
                return await self.probe(coro_fn, item)

        results = await asyncio.gather(*[_guarded(it) for it in items], return_exceptions=True)
        return [r if not isinstance(r, Exception) else None for r in results]

    def get_stats(self) -> dict:
        """Return current adaptive scan statistics."""
        return {
            "mode": self.stats.mode.value,
            "probes_sent": self.stats.probes_sent,
            "probes_succeeded": self.stats.probes_succeeded,
            "probes_dropped": self.stats.probes_dropped,
            "drop_rate_pct": round(self.stats.drop_rate * 100, 2),
            "avg_latency_ms": round(self.stats.avg_latency_ms, 2),
            "current_delay_s": round(self.stats.current_delay, 3),
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _pre_probe_delay(self) -> None:
        """
        Sleep before each probe using a Poisson-distributed interval.

        Poisson inter-arrival times are statistically indistinguishable from
        organic browsing traffic, defeating IDS rules that flag uniform scan
        cadence. Stealth mode uses a longer mean; aggressive mode skips delay.
        """
        base = self._mode_delay.get(self.mode, self.stats.current_delay)
        if base <= 0:
            return
        # Poisson sample for non-uniform timing
        delay = evasion.poisson_delay(base)
        # Clamp to sane range so stealth doesn't wait forever
        delay = min(delay, self.max_delay * 2)
        await asyncio.sleep(delay)

    def _record_success(self, latency_ms: float) -> None:
        self.stats.probes_sent += 1
        self.stats.probes_succeeded += 1
        self.stats.total_latency_ms += latency_ms
        self.stats.consecutive_drops = 0
        if self.mode == ScanMode.ADAPTIVE:
            self._tune_delay(latency_ms)

    def _record_drop(self) -> None:
        self.stats.probes_sent += 1
        self.stats.probes_dropped += 1
        self.stats.consecutive_drops += 1
        if self.mode == ScanMode.ADAPTIVE:
            self._escalate_delay()

    def _tune_delay(self, latency_ms: float) -> None:
        """Decrease delay when responses are fast and reliable."""
        avg = self.stats.avg_latency_ms or latency_ms
        if latency_ms > avg * self._LATENCY_SPIKE_FACTOR:
            self._escalate_delay()
        elif self.stats.drop_rate < 0.05:
            # Good conditions — cautiously speed up
            self.stats.current_delay = max(
                self.min_delay,
                self.stats.current_delay * 0.9,
            )

    def _escalate_delay(self) -> None:
        """Increase delay when drops or latency spikes are observed."""
        new_delay = min(self.max_delay, self.stats.current_delay * 1.5)
        if new_delay != self.stats.current_delay:
            logger.info(
                "Adaptive engine slowing down: %.2fs → %.2fs (drop-rate=%.1f%%)",
                self.stats.current_delay,
                new_delay,
                self.stats.drop_rate * 100,
            )
            self.stats.current_delay = new_delay

    def _backoff_delay(self, attempt: int) -> float:
        """Exponential back-off with jitter for retry waits."""
        base = min(self.max_delay, 2 ** attempt * self.min_delay)
        return base + random.uniform(0, base * 0.5)

    def _effective_concurrency(self, requested: int) -> int:
        """Reduce concurrency when drop rate is high."""
        if self.stats.drop_rate > self._DROP_RATE_THRESHOLD:
            reduced = max(1, requested // 2)
            logger.info(
                "High drop rate (%.1f%%) — reducing concurrency %d → %d",
                self.stats.drop_rate * 100,
                requested,
                reduced,
            )
            return reduced
        if self.stats.consecutive_drops >= self._MAX_CONSECUTIVE_DROPS:
            return max(1, requested // 4)
        return requested
