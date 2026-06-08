"""Cached MonarchMoney client factory.

Resolution order for an authenticated client:

1. A previously persisted session token (keyring, or the ``SESSION_STORE_PATH``
   file in a container) -- reused across cold starts.
2. Headless login from ``MONARCH_EMAIL`` / ``MONARCH_PASSWORD``, completing MFA
   non-interactively with a TOTP code derived from ``MONARCH_MFA_SECRET`` via
   ``pyotp`` when Monarch requires it.

Startup never blocks on auth: the client is built lazily on the first tool call.
If Monarch auth is unavailable the failing tool returns a clear message rather
than crashing the server. Expired sessions are detected and trigger a re-login.
"""

import logging
import os
from typing import Optional

from monarchmoney import MonarchMoney
from monarchmoney.monarchmoney import MonarchMoneyEndpoints

from monarch_mcp_server.secure_session import secure_session

logger = logging.getLogger(__name__)

# Patch MonarchMoney to use new API domain
MonarchMoneyEndpoints.BASE_URL = "https://api.monarch.com"

# Module-level client cache
_cached_client: Optional[MonarchMoney] = None


class MonarchAuthError(RuntimeError):
    """Raised when no usable Monarch session can be established."""


def clear_client_cache() -> None:
    """Clear the cached client. Call after re-authentication or expiry."""
    global _cached_client
    _cached_client = None
    logger.info("Client cache cleared")


def _totp_code() -> Optional[str]:
    """Current TOTP code from ``MONARCH_MFA_SECRET``, or None if unset."""
    secret = os.getenv("MONARCH_MFA_SECRET")
    if not secret or not secret.strip():
        return None
    import pyotp

    return pyotp.TOTP(secret.strip().replace(" ", "")).now()


async def _login_with_env_credentials() -> MonarchMoney:
    """Perform a fully non-interactive login using environment credentials.

    Completes MFA with a TOTP code when Monarch demands it. The resulting
    session token is persisted so subsequent cold starts skip the login.
    """
    from monarchmoney import RequireMFAException

    email = os.getenv("MONARCH_EMAIL")
    password = os.getenv("MONARCH_PASSWORD")
    if not (email and password):
        raise MonarchAuthError(
            "Monarch authentication unavailable: no saved session and "
            "MONARCH_EMAIL / MONARCH_PASSWORD are not set."
        )

    client = MonarchMoney()
    try:
        await client.login(
            email,
            password,
            use_saved_session=False,
            save_session=False,
        )
    except RequireMFAException:
        code = _totp_code()
        if not code:
            raise MonarchAuthError(
                "Monarch requires MFA but MONARCH_MFA_SECRET is not set. "
                "Provide the TOTP secret to enable headless login."
            )
        await client.multi_factor_authenticate(email, password, code)

    secure_session.save_authenticated_session(client)
    logger.info("Logged into Monarch Money with environment credentials")
    return client


async def _is_session_valid(client: MonarchMoney) -> bool:
    """Cheap liveness check to detect an expired/invalid session token."""
    try:
        await client.get_subscription_details()
        return True
    except Exception as exc:
        logger.info("Stored Monarch session is invalid/expired: %s", type(exc).__name__)
        return False


async def get_monarch_client() -> MonarchMoney:
    """Get or create a cached, authenticated MonarchMoney client.

    Raises ``MonarchAuthError`` (with a user-facing message) when no session can
    be established, so individual tool calls fail clearly instead of hanging.
    """
    global _cached_client

    if _cached_client is not None:
        return _cached_client

    # 1. Reuse a persisted session if it is still valid.
    client = secure_session.get_authenticated_client()
    if client is not None:
        if await _is_session_valid(client):
            logger.info("Using persisted Monarch session")
            _cached_client = client
            return client
        # Expired: drop it and fall through to a fresh login.
        secure_session.delete_token()

    # 2. Headless login from environment credentials (+ TOTP MFA).
    client = await _login_with_env_credentials()
    _cached_client = client
    return client
