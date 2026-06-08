"""OAuth 2.0 Resource Server: JWT bearer-token verification.

Implements ``mcp.server.auth.provider.TokenVerifier`` for the installed MCP SDK
(verified against mcp 1.27.x). FastMCP wires this verifier into its Starlette
app: it adds the bearer-auth middleware, returns ``401`` with a
``WWW-Authenticate`` header pointing at the protected-resource metadata, and
serves ``/.well-known/oauth-protected-resource`` (RFC 9728) automatically when
``AuthSettings.resource_server_url`` is set.

We validate, per the MCP authorization spec (2025-06-18):
  * JWT signature against the IdP JWKS (fetched and cached from OAUTH_JWKS_URI)
  * ``iss`` == OAUTH_ISSUER
  * ``aud`` == OAUTH_AUDIENCE (this server's resource id) -- the #1 failure mode
  * ``exp`` / ``nbf`` (enforced by PyJWT)

Audience mismatch returns ``None`` here, which the SDK surfaces as a 401, so the
client knows to re-acquire a token with the correct ``resource`` indicator.
"""

from __future__ import annotations

import logging
from typing import Any

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken, TokenVerifier

from monarch_mcp_server.config import OAuthConfig

logger = logging.getLogger(__name__)

# Algorithms we accept. Asymmetric only -- never allow "none" or HMAC, which
# would let a client forge tokens using public material.
_ALLOWED_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]


def _parse_scopes(claims: dict[str, Any]) -> list[str]:
    """Extract granted scopes from a token.

    Different IdPs encode scopes differently: OAuth's ``scope`` is a
    space-delimited string (Auth0, Zitadel); some use a ``scp`` array.
    """
    scope = claims.get("scope")
    if isinstance(scope, str):
        return scope.split()
    scp = claims.get("scp")
    if isinstance(scp, list):
        return [str(s) for s in scp]
    if isinstance(scp, str):
        return scp.split()
    return []


class JwtTokenVerifier(TokenVerifier):
    """Validate IdP-issued JWT access tokens for this resource server."""

    def __init__(self, oauth: OAuthConfig) -> None:
        if not oauth.enabled:  # pragma: no cover - guarded by caller
            raise ValueError("OAuth is not fully configured; cannot build verifier")
        self._issuer = oauth.issuer
        # Accept the configured audience with and without a trailing slash. The
        # SDK's RFC 9728 metadata route normalises the resource id to a trailing
        # slash; without this, a token whose `aud` matches the IdP's API
        # identifier (no slash) but not the advertised resource would be
        # rejected. PyJWT passes if the token's aud matches ANY entry.
        raw_aud = oauth.resource_id or ""
        self._audience = list({raw_aud, raw_aud.rstrip("/"), raw_aud.rstrip("/") + "/"})
        # PyJWKClient fetches the JWKS lazily and caches keys (with its own
        # lifespan + LRU), so signing keys are not re-fetched on every request.
        self._jwks_client = PyJWKClient(
            oauth.jwks_uri,  # type: ignore[arg-type]
            cache_keys=True,
            lifespan=600,
        )
        logger.info(
            "OAuth resource server enabled (issuer=%s, audience=%s)",
            self._issuer,
            self._audience,
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an ``AccessToken`` for a valid JWT, or ``None`` to reject.

        Returning ``None`` makes the SDK respond 401 with a WWW-Authenticate
        header. We never log the token itself, only the failure reason.
        """
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=_ALLOWED_ALGS,
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            logger.info("Bearer token rejected: expired")
            return None
        except jwt.InvalidAudienceError:
            # Most common misconfiguration: token minted for a different API.
            logger.warning(
                "Bearer token rejected: audience mismatch (expected %s). "
                "Check the IdP API identifier / 'resource' indicator.",
                self._audience,
            )
            return None
        except jwt.InvalidIssuerError:
            logger.warning("Bearer token rejected: issuer mismatch (expected %s)", self._issuer)
            return None
        except jwt.PyJWTError as exc:
            logger.info("Bearer token rejected: %s", type(exc).__name__)
            return None
        except Exception as exc:  # network/JWKS errors
            logger.warning("Bearer token verification error: %s", type(exc).__name__)
            return None

        scopes = _parse_scopes(claims)
        client_id = (
            claims.get("azp")
            or claims.get("client_id")
            or claims.get("sub")
            or "unknown"
        )
        expires_at = claims.get("exp")
        return AccessToken(
            token=token,
            client_id=str(client_id),
            scopes=scopes,
            expires_at=int(expires_at) if expires_at is not None else None,
            subject=str(claims["sub"]) if claims.get("sub") else None,
            claims=claims,
        )
