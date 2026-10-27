"""Token buckets for the budgets (P, U, stats cap)."""

import time


class TokenBucket:
    """rate=None means unlimited (the budget is not enforced)."""

    def __init__(self, rate, burst=None, clock=time.monotonic):
        self.rate = rate
        self.burst = max(1.0, float(burst if burst is not None else (rate or 1)))
        self.clock = clock
        self.tokens = self.burst
        self.last = clock()

    @property
    def unlimited(self):
        return self.rate is None

    def _refill(self):
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
        self.last = now

    def take(self, n=1):
        if self.unlimited:
            return True
        self._refill()
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

    def take_debt(self, n=1):
        """Take n tokens if the bucket is not in debt; the balance may go
        negative by up to n. Used for P: a packet-out never waits behind queued
        Packet-Ins, and the debt delays the next Packet-In instead."""
        if self.unlimited:
            return True
        self._refill()
        if self.tokens >= 0:
            self.tokens -= n
            return True
        return False

    def wait_time(self, n=1):
        """Seconds until `n` tokens are available (0 if available now)."""
        if self.unlimited:
            return 0.0
        self._refill()
        return max(0.0, (n - self.tokens) / self.rate)
