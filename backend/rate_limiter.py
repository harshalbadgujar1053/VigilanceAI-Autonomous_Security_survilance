"""
Steady-rate limiter for Gemini calls: guarantees no more than `rate_per_minute`
requests in ANY rolling 60-second window (not just clock-aligned minutes).

Why not a simple "15 per minute, reset the counter" approach: that allows
15 requests at 0:59 and another 15 at 1:00 — 30 in 2 seconds, still over
the real limit. A steady drip (1 request every 60/rate_per_minute seconds)
avoids this entirely.

Usage:
    limiter = SteadyRateLimiter(rate_per_minute=15)
    await limiter.acquire()   # blocks until it's safe to proceed
    # ... make the Gemini call ...
"""
import asyncio
import time


class SteadyRateLimiter:
    def __init__(self, rate_per_minute: int):
        self.interval = 60.0 / rate_per_minute  # seconds between allowed requests
        self._lock = asyncio.Lock()
        self._next_allowed_at = 0.0

    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            wait = self._next_allowed_at - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            # Schedule the next slot from whichever is later: now, or the
            # previously scheduled slot + interval (keeps spacing exact
            # even if this call was delayed).
            self._next_allowed_at = max(now, self._next_allowed_at) + self.interval
