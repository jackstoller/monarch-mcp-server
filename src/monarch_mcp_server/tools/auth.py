"""Authentication tools."""

import logging
import os

from mcp.server.fastmcp import Context

from monarch_mcp_server import auth
from monarch_mcp_server.app import mcp
from monarch_mcp_server.config import config
from monarch_mcp_server.security import write_tool
from monarch_mcp_server.secure_session import secure_session

logger = logging.getLogger(__name__)


def _stdio_only(decorator):
    """Elicitation/keyring login is a local single-user flow; in multi-user HTTP
    mode accounts are managed on the web UI instead."""
    return (lambda func: func) if config.is_http else decorator


def _web_url() -> str:
    return config.oauth.public_url or "the server's web page"


@mcp.tool()
async def setup_authentication() -> str:
    """Get instructions for setting up secure authentication with Monarch Money."""
    if config.is_http:
        return (
            f"Open {_web_url()} in a browser, sign in, and connect your Monarch "
            "account on the dashboard. Credentials are encrypted at rest and "
            "never pass through the model."
        )
    return """🔐 Monarch Money - Authentication Options

Option 1: Elicitation login (Recommended for interactive clients)
   Call 'monarch_login' to enter email/password (and MFA if needed)
   via a secure form in your client UI. Credentials never pass
   through the model. Or 'monarch_login_with_token' to paste a
   browser-copied session token.

Option 2: Email/Password (Terminal)
   Run in terminal: python login_setup.py

Call 'monarch_logout' to clear the stored session.

✅ Session persists across restarts
✅ Token stored securely in system keyring"""


@_stdio_only(write_tool())
async def monarch_login(ctx: Context) -> str:
    """Sign in to Monarch Money.

    Opens a secure form in the client UI to collect email, password, and
    (if required) an MFA code. Credentials never pass through the model —
    they flow client-UI → server directly via the MCP protocol.
    """
    return await auth.login_interactive(ctx)


@_stdio_only(write_tool())
async def monarch_login_with_token(ctx: Context) -> str:
    """Sign in to Monarch Money using a browser-copied session token.

    Useful for SSO users who can't use password login. Grab the token from
    browser DevTools → Application → Local Storage → app.monarchmoney.com.
    """
    return await auth.login_with_token_interactive(ctx)


@_stdio_only(write_tool())
async def monarch_logout() -> str:
    """Clear the stored Monarch Money session from the system keyring."""
    return await auth.logout()


@mcp.tool()
async def check_auth_status() -> str:
    """Check if already authenticated with Monarch Money."""
    if config.is_http:
        return _http_auth_status()
    try:
        token = secure_session.load_token()
        if token:
            status = "✅ Authentication token found in secure keyring storage\n"
        else:
            status = "❌ No authentication token found in keyring\n"

        email = os.getenv("MONARCH_EMAIL")
        if email:
            status += f"📧 Environment email: {email}\n"

        status += (
            "\n💡 Try get_accounts to test connection or run login_setup.py if needed."
        )

        return status
    except Exception as e:
        return f"Error checking auth status: {str(e)}"


@mcp.tool()
async def debug_session_loading() -> str:
    """Debug keyring session loading issues."""
    if config.is_http:
        return "Not applicable: sessions are stored per user in the server database."
    try:
        token = secure_session.load_token()
        if token:
            return "✅ Token found in keyring."
        return "❌ No token found in keyring. Run login_setup.py to authenticate."
    except Exception as e:
        logger.exception("Keyring access failed")
        return f"❌ Keyring access failed: {type(e).__name__}: {e}"


def _http_auth_status() -> str:
    from monarch_mcp_server.client import _current_user_id
    from monarch_mcp_server.store import get_store

    meta = get_store().connection_meta(_current_user_id())
    if meta is None:
        return f"❌ No Monarch account connected. Connect one at {_web_url()}"
    if meta["status"] == "ok":
        return "✅ Monarch account connected and healthy."
    return (
        f"⚠️ Monarch connection needs attention ({meta['last_error'] or 'unknown'}). "
        f"Reconnect at {_web_url()}"
    )
