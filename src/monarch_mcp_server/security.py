"""Tool-registration helpers enforcing read-only mode and OAuth scopes.

Two layers protect mutating ("write") tools:

1. ``READ_ONLY`` (default true): write tools are simply **not registered**, so
   they never appear in the tool list and cannot be called at all.

2. When writes are enabled and OAuth is active, each write tool additionally
   requires the ``monarch:write`` scope in the caller's token at call time.

Read scope (``monarch:read``) is enforced globally by the SDK's
``RequireAuthMiddleware`` via ``AuthSettings.required_scopes`` -- every MCP
request must carry it -- so read tools need no extra wrapper here.

The SDK's middleware can only enforce a single global scope set per request, not
per-tool scopes; that is why the write scope is checked here, inside the tool,
using the authenticated-token contextvar the SDK exposes.
"""

from __future__ import annotations

import functools
import inspect
import logging
from typing import Any, Callable

from mcp.server.auth.middleware.auth_context import get_access_token

from monarch_mcp_server.config import config

logger = logging.getLogger(__name__)


def _mcp():
    """Lazily resolve the FastMCP instance.

    Imported lazily (not at module top) to avoid a circular import: ``app``
    imports the tool modules, which import this module.
    """
    from monarch_mcp_server.app import mcp

    return mcp


class WriteScopeRequired(Exception):
    """Raised when a write tool is called without the required scope."""


def _check_write_scope() -> None:
    """Ensure the current request's token carries the write scope.

    No-op when OAuth is disabled (e.g. local stdio). The access token is only
    present for HTTP requests that passed bearer auth.
    """
    if not config.oauth.enabled:
        return
    token = get_access_token()
    if token is None:
        raise WriteScopeRequired("Authentication required for this write operation.")
    if config.oauth.write_scope not in (token.scopes or []):
        raise WriteScopeRequired(
            f"Missing required scope '{config.oauth.write_scope}' for this write "
            "operation. Reconnect granting write access."
        )


def read_tool(*args: Any, **kwargs: Any) -> Callable[[Callable], Callable]:
    """Register a read-only tool. Thin alias for ``mcp.tool()`` for symmetry."""
    return _mcp().tool(*args, **kwargs)


def write_tool(*args: Any, **kwargs: Any) -> Callable[[Callable], Callable]:
    """Register a mutating tool, gated by ``READ_ONLY`` and the write scope.

    When ``READ_ONLY`` is set the tool is not registered and the original
    function is returned untouched (so module-level re-exports still resolve).
    """

    def decorator(func: Callable) -> Callable:
        if config.read_only:
            logger.info("READ_ONLY: not registering write tool %r", func.__name__)
            return func

        @functools.wraps(func)
        async def wrapper(*a: Any, **k: Any) -> Any:
            _check_write_scope()
            return await func(*a, **k)

        # Preserve the original signature so FastMCP builds the correct schema
        # (Context params, typed args) from the wrapped function.
        wrapper.__signature__ = inspect.signature(func)  # type: ignore[attr-defined]
        return _mcp().tool(*args, **kwargs)(wrapper)

    return decorator
