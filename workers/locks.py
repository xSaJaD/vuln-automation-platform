"""قفل تزامن موزّع عبر Redis (SET NX EX)."""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from api.config import settings


@contextlib.contextmanager
def redis_lock(key: str, ttl: int = 3600) -> Iterator[bool]:
    """يحجز قفلًا باسم key لمدة ttl ثانية. يُرجِع True لو نجح الحجز."""
    from redis import Redis

    client = Redis.from_url(settings.redis_url or "redis://localhost:6379/0")
    acquired = bool(client.set(key, "1", nx=True, ex=ttl))
    try:
        yield acquired
    finally:
        if acquired:
            with contextlib.suppress(Exception):
                client.delete(key)
