"""Minimal in-memory rate limiting for the HTTP transport.

A fixed-window counter keyed by client IP. This is deliberately simple: it
protects a single instance against trivial abuse and is not a substitute for a
proper limiter at the ingress when running multiple replicas (state is
per-process and not shared -- see README "Kubernetes" notes).

The ``/healthz`` endpoint is exempt so liveness probes are never throttled.
"""

from __future__ import annotations

import time
from collections import defaultdict

from starlette.requests import Request
from starlette.responses import JSONResponse


class RateLimitMiddleware:
    """ASGI middleware enforcing a per-IP request budget each minute."""

    def __init__(self, app, limit_per_minute: int = 120) -> None:
        self.app = app
        self.limit = limit_per_minute
        self._window: int = 0
        self._counts: dict[str, int] = defaultdict(int)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        if request.url.path == "/healthz":
            await self.app(scope, receive, send)
            return

        # Prefer the proxy-forwarded client IP (TLS terminates upstream).
        forwarded = request.headers.get("x-forwarded-for")
        client_ip = (
            forwarded.split(",")[0].strip()
            if forwarded
            else (request.client.host if request.client else "unknown")
        )

        now_window = int(time.time() // 60)
        if now_window != self._window:
            self._window = now_window
            self._counts.clear()

        self._counts[client_ip] += 1
        if self._counts[client_ip] > self.limit:
            response = JSONResponse(
                {"error": "rate_limited", "error_description": "Too many requests"},
                status_code=429,
                headers={"Retry-After": "60"},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
