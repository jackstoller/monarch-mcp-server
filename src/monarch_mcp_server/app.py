"""FastMCP application instance and entry point.

Supports two transports via the ``TRANSPORT`` env var:

* ``stdio`` (default in code, for Claude Desktop/Code and ``mcp run``)
* ``http``  -- Streamable HTTP bound to ``0.0.0.0:$PORT`` for remote deployment,
  protected as an OAuth 2.0 Resource Server when OAuth env vars are configured.

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
    """Construct the FastMCP instance, wiring OAuth resource-server protection
    when the OAuth env vars are present."""
    kwargs: dict = {
        "host": config.host,
        "port": config.port,
        "streamable_http_path": config.mcp_path,
    }

    if config.oauth.enabled:
        from mcp.server.auth.settings import AuthSettings

        from monarch_mcp_server.oauth import JwtTokenVerifier

        # required_scopes is enforced on EVERY request by the SDK middleware, so
        # we require only the read scope globally; the write scope is checked
        # per-tool in security.py.
        kwargs["token_verifier"] = JwtTokenVerifier(config.oauth)
        kwargs["auth"] = AuthSettings(
            issuer_url=config.oauth.issuer,
            resource_server_url=config.oauth.resource_id,
            required_scopes=[config.oauth.read_scope],
        )
    elif config.is_http:
        logger.warning(
            "TRANSPORT=http but OAuth is not configured (OAUTH_ISSUER/"
            "OAUTH_AUDIENCE/OAUTH_JWKS_URI). The server will run UNAUTHENTICATED. "
            "Set the OAuth vars before exposing this publicly."
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


# Import tools package to trigger tool registration (read tools via @mcp.tool(),
# write tools via security.write_tool()). Imported after `mcp` exists.
import monarch_mcp_server.tools  # noqa: E402, F401

# Export for `mcp run`
app = mcp


def main() -> None:
    """Main entry point for the server."""
    logger.info(
        "Starting Monarch Money MCP Server (transport=%s, read_only=%s, oauth=%s)",
        config.transport,
        config.read_only,
        config.oauth.enabled,
    )
    try:
        if config.is_http:
            _run_http()
        else:
            mcp.run()  # stdio (default)
    except Exception as e:
        logger.error(f"Failed to run server: {str(e)}")
        raise


def _run_http() -> None:
    """Serve the Streamable HTTP app with optional rate limiting."""
    import uvicorn

    starlette_app = mcp.streamable_http_app()

    if config.rate_limit_per_minute > 0:
        from monarch_mcp_server.ratelimit import RateLimitMiddleware

        starlette_app.add_middleware(
            RateLimitMiddleware,
            limit_per_minute=config.rate_limit_per_minute,
        )

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
