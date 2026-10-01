"""Cached MonarchMoney client factory.

HTTP (multi-user) mode: the caller's OAuth access token carries a user id; that
user's connection is loaded from the encrypted store, validated, and cached. A
dead session is transparently renewed from the stored credentials (+ TOTP) when
the user opted into that, otherwise the dashboard shows "needs reconnect".

stdio (single-user) mode -- resolution order for an authenticated client:

1. A previously persisted session token (keyring, or the ``SESSION_STORE_PATH``
   file) -- reused across cold starts.
2. Headless login from ``MONARCH_EMAIL`` / ``MONARCH_PASSWORD``, completing MFA
   non-interactively with a TOTP code derived from ``MONARCH_MFA_SECRET``.

Startup never blocks on auth: clients are built lazily on the first tool call.
If Monarch auth is unavailable the failing tool returns a clear message rather
than crashing the server.
"""

import asyncio
import logging
import os
import time
from typing import Optional

from monarchmoney import MonarchMoney
from monarchmoney.monarchmoney import MonarchMoneyEndpoints

from monarch_mcp_server.config import config
from monarch_mcp_server.secure_session import secure_session
from monarch_mcp_server.store import get_store

logger = logging.getLogger(__name__)

# Patch MonarchMoney to use new API domain
MonarchMoneyEndpoints.BASE_URL = "https://api.monarch.com"

# stdio-mode client cache
_cached_client: Optional[MonarchMoney] = None


class MonarchAuthError(RuntimeError):
    """Raised when no usable Monarch session can be established."""


def clear_client_cache() -> None:
    """Clear the stdio cached client. Call after re-authentication or expiry."""
    global _cached_client
    _cached_client = None
    logger.info("Client cache cleared")


def _totp_code(secret: Optional[str] = None) -> Optional[str]:
    """Current TOTP code from ``secret`` (default ``MONARCH_MFA_SECRET``)."""
    secret = secret if secret is not None else os.getenv("MONARCH_MFA_SECRET")
    if not secret or not secret.strip():
        return None
    import pyotp

    return pyotp.TOTP(secret.strip().replace(" ", "")).now()


async def monarch_login(
    email: str,
    password: str,
    *,
    mfa_secret: Optional[str] = None,
    mfa_code: Optional[str] = None,
) -> MonarchMoney:
    """Non-interactive Monarch login; completes MFA from a TOTP secret or a
    one-time code. Raises ``MonarchAuthError`` with a user-facing message."""
    from monarchmoney import RequireMFAException

    client = MonarchMoney()
    try:
        await client.login(
            email, password, use_saved_session=False, save_session=False
        )
    except RequireMFAException:
        code = _totp_code(mfa_secret) if mfa_secret else (mfa_code or "").strip()
        if not code:
            raise MonarchAuthError(
                "Monarch requires MFA: provide your authenticator secret (for "
                "automatic renewal) or a current 6-digit code."
            )
        try:
            await client.multi_factor_authenticate(email, password, code)
        except Exception as exc:
            raise MonarchAuthError("Monarch rejected the MFA code.") from exc
    except Exception as exc:
        raise MonarchAuthError(
            f"Monarch sign-in failed ({type(exc).__name__}). Check your email "
            "and password."
        ) from exc
    return client


async def _login_with_env_credentials() -> MonarchMoney:
    """stdio mode: headless login from the environment; the session token is
    persisted so the next cold start skips the login."""
    email = os.getenv("MONARCH_EMAIL")
    password = os.getenv("MONARCH_PASSWORD")
    if not (email and password):
        raise MonarchAuthError(
            "Monarch authentication unavailable: no saved session and "
            "MONARCH_EMAIL / MONARCH_PASSWORD are not set."
        )
    client = await monarch_login(
        email, password, mfa_secret=os.getenv("MONARCH_MFA_SECRET")
    )
    secure_session.save_authenticated_session(client)
    logger.info("Logged into Monarch Money with environment credentials")
    return client


async def is_session_valid(client: MonarchMoney) -> bool:
    """Cheap liveness check to detect an expired/invalid session token."""
    try:
        await client.get_subscription_details()
        return True
    except Exception as exc:
        logger.info("Monarch session is invalid/expired: %s", type(exc).__name__)
        return False


# -- multi-user (HTTP) --------------------------------------------------------

_REVALIDATE_SECS = 600
_user_clients: dict[str, tuple[MonarchMoney, float]] = {}
_user_locks: dict[str, asyncio.Lock] = {}


def clear_user_client(user_id: str) -> None:
    """Drop a user's cached client (call after their connection changes)."""
    _user_clients.pop(user_id, None)


def _current_user_id() -> str:
    from mcp.server.auth.middleware.auth_context import get_access_token

    token = get_access_token()
    if token is None or not token.subject:
        raise MonarchAuthError("Not authenticated.")
    return token.subject


def _reconnect_hint() -> str:
    where = config.oauth.public_url or "the server's web page"
    return f"Open {where} and (re)connect your Monarch account."


async def _build_user_client(user_id: str) -> MonarchMoney:
    store = get_store()
    conn = store.get_connection(user_id)
    meta = store.connection_meta(user_id)
    if not conn or not meta:
        raise MonarchAuthError(f"No Monarch account connected. {_reconnect_hint()}")

    if conn.get("token"):
        client = MonarchMoney(token=conn["token"])
        if await is_session_valid(client):
            store.set_connection_health(user_id, "ok")
            return client

    # Session missing/expired: renew from stored credentials if the user kept them.
    if conn.get("email") and conn.get("password"):
        try:
            client = await monarch_login(
                conn["email"], conn["password"], mfa_secret=conn.get("mfa_secret")
            )
        except MonarchAuthError as exc:
            store.set_connection_health(user_id, "error", str(exc))
            raise MonarchAuthError(f"{exc} {_reconnect_hint()}") from exc
        conn["token"] = client.token
        store.save_connection(user_id, conn, method=meta["method"], label=meta["label"])
        logger.info("Renewed a Monarch session from stored credentials")
        return client

    msg = "Monarch session expired."
    store.set_connection_health(user_id, "error", msg)
    raise MonarchAuthError(f"{msg} {_reconnect_hint()}")


async def get_user_client(user_id: str) -> MonarchMoney:
    lock = _user_locks.setdefault(user_id, asyncio.Lock())
    async with lock:
        cached = _user_clients.get(user_id)
        if cached:
            client, checked = cached
            if time.monotonic() - checked < _REVALIDATE_SECS:
                return client
            if await is_session_valid(client):
                _user_clients[user_id] = (client, time.monotonic())
                return client
            _user_clients.pop(user_id, None)
        client = await _build_user_client(user_id)
        _user_clients[user_id] = (client, time.monotonic())
        return client


async def check_user_health(user_id: str) -> tuple[bool, str | None]:
    """Force a live check (and renewal if possible); records the result."""
    clear_user_client(user_id)
    try:
        await get_user_client(user_id)
    except MonarchAuthError as exc:
        return False, str(exc)
    return True, None


# -- entry point used by every tool --------------------------------------------


async def get_monarch_client() -> MonarchMoney:
    """Authenticated client for the current caller.

    HTTP mode resolves the OAuth subject to that user's own Monarch connection;
    stdio mode uses the single local session. Raises ``MonarchAuthError`` (with a
    user-facing message) so tool calls fail clearly instead of hanging.
    """
    if config.is_http:
        return await get_user_client(_current_user_id())
    return await _get_local_client()


async def _get_local_client() -> MonarchMoney:
    global _cached_client

    if _cached_client is not None:
        return _cached_client

    # 1. Reuse a persisted session if it is still valid.
    client = secure_session.get_authenticated_client()
    if client is not None:
        if await is_session_valid(client):
            logger.info("Using persisted Monarch session")
            _cached_client = client
            return client
        # Expired: drop it and fall through to a fresh login.
        secure_session.delete_token()

    # 2. Headless login from environment credentials (+ TOTP MFA).
    client = await _login_with_env_credentials()
    _cached_client = client
    return client
