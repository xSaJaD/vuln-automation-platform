"""محدّد معدّل بسيط (نافذة ثابتة) في الذاكرة — لكل مفتاح (IP).

كافٍ لمنصة self-hosted بعملية واحدة. للتوسّع متعدد العمّال يُستبدَل لاحقًا بـ Redis.
"""

from __future__ import annotations

import threading
import time


class RateLimiter:
    def __init__(self, limit: int, window: int = 60):
        self.limit = limit
        self.window = window
        self._hits: dict[str, list] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None or now - bucket[0] >= self.window:
                self._hits[key] = [now, 1]
                return True
            if bucket[1] < self.limit:
                bucket[1] += 1
                return True
            return False
