"""FastMCP application instance and entry point.

Supports two transports via the ``TRANSPORT`` env var:

* ``stdio`` (default in code, for Claude Desktop/Code and ``mcp run``)
* ``http``  -- multi-user service on ``0.0.0.0:$PORT``: web UI (sign up, connect
  Monarch, health, connector instructions) plus the MCP endpoint at ``MCP_PATH``,
  protected by a built-in OAuth 2.1 authorization server (no external IdP).

TLS is expected to terminate at an upstream ingress/reverse proxy; this process
serves plain HTTP.
"""

import logging
from pathlib import Path

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from monarch_mcp_server.config import config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


def _build_fastmcp() -> FastMCP:
    """Construct the FastMCP instance. In HTTP mode this app is its own OAuth
    authorization server (see ``provider.py``) and serves the web UI."""
    kwargs: dict = {
        "host": config.host,
        "port": config.port,
        "streamable_http_path": config.mcp_path,
    }

    if config.is_http:
        from mcp.server.auth.settings import (
            AuthSettings,
            ClientRegistrationOptions,
            RevocationOptions,
        )

        from monarch_mcp_server.provider import MonarchOAuthProvider, allowed_scopes

        if not config.oauth.public_url:
            raise RuntimeError(
                "PUBLIC_URL must be set for the HTTP transport (e.g. "
                "https://monarch.example.com); it is the OAuth issuer."
            )
        # required_scopes is enforced on EVERY request by the SDK middleware, so
        # we require only the read scope globally; the write scope is checked
        # per-tool in security.py.
        kwargs["auth_server_provider"] = MonarchOAuthProvider()
        kwargs["auth"] = AuthSettings(
            issuer_url=config.oauth.public_url,
            resource_server_url=config.oauth.resource_id,
            required_scopes=[config.oauth.read_scope],
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=allowed_scopes(),
                default_scopes=allowed_scopes(),
            ),
            revocation_options=RevocationOptions(enabled=True),
        )

    return FastMCP("Monarch Money MCP Server", **kwargs)


# Initialize FastMCP server
mcp = _build_fastmcp()


@mcp.custom_route("/healthz", methods=["GET"])
async def healthz(_request: Request) -> JSONResponse:
    """Unauthenticated liveness probe (not part of the MCP protocol)."""
    return JSONResponse({"status": "ok"})


# Serve a favicon at the connector origin so clients (e.g. the Claude app) show
# this server's icon instead of falling back to the registrable domain's. Public
# and cacheable; not part of the MCP protocol.
_FAVICON_PATH = Path(__file__).parent / "static" / "favicon.ico"
_FAVICON_BYTES = _FAVICON_PATH.read_bytes() if _FAVICON_PATH.is_file() else b""


@mcp.custom_route("/favicon.ico", methods=["GET"])
async def favicon(_request: Request) -> Response:
    if not _FAVICON_BYTES:
        return Response(status_code=404)
    return Response(
        content=_FAVICON_BYTES,
        media_type="image/x-icon",
        headers={"Cache-Control": "public, max-age=86400"},
    )


if config.is_http:
    from monarch_mcp_server.web import register_routes

    register_routes(mcp)

# Import tools package to trigger tool registration (read tools via @mcp.tool(),
# write tools via security.write_tool()). Imported after `mcp` exists.
import monarch_mcp_server.tools  # noqa: E402, F401

# Export for `mcp run`
app = mcp


def main() -> None:
    """Main entry point for the server."""
    logger.info(
        "Starting Monarch Money MCP Server (transport=%s, read_only=%s, signup=%s)",
        config.transport,
        config.read_only,
        config.allow_signup,
    )
    try:
        if config.is_http:
            _run_http()
        else:
            mcp.run()  # stdio (default)
    except Exception as e:
        logger.error(f"Failed to run server: {str(e)}")
        raise


def build_http_app():
    """The Starlette app: MCP endpoint, OAuth server, web UI, hardening."""
    from monarch_mcp_server.web import SecurityHeaders

    starlette_app = mcp.streamable_http_app()
    starlette_app.add_middleware(SecurityHeaders)

    if config.rate_limit_per_minute > 0:
        from monarch_mcp_server.ratelimit import RateLimitMiddleware

        starlette_app.add_middleware(
            RateLimitMiddleware,
            limit_per_minute=config.rate_limit_per_minute,
        )
    return starlette_app


def _run_http() -> None:
    """Serve the HTTP app with uvicorn."""
    import uvicorn

    starlette_app = build_http_app()

    logger.info(
        "Streamable HTTP listening on %s:%s%s",
        config.host,
        config.port,
        mcp.settings.streamable_http_path,
    )
    uvicorn.run(
        starlette_app,
        host=config.host,
        port=config.port,
        log_level="info",
        # Do NOT trust client-settable X-Forwarded-* headers. Nothing in the
        # auth path depends on the request scheme (metadata/WWW-Authenticate use
        # the configured PUBLIC_URL), and the rate limiter reads the
        # Cloudflare-set CF-Connecting-IP directly, so trusting forwarded headers
        # would only add a spoofing surface.
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
