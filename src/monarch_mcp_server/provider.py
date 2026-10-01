"""Built-in OAuth 2.1 authorization server (replaces any external IdP).

Plugs into the MCP SDK's ``auth_server_provider`` hook, which supplies the
standard endpoints (``/authorize``, ``/token``, ``/register`` for dynamic client
registration, ``/revoke`` and the discovery metadata) and enforces PKCE and
redirect-URI matching. This class supplies the storage and the one piece the SDK
leaves to us: the user-facing login + consent step, served by ``web.py``.

Tokens are opaque random strings (only their hash is stored) bound to a user id,
which becomes ``AccessToken.subject``; ``client.get_monarch_client`` uses it to
pick that user's Monarch connection.
"""

from __future__ import annotations

import time

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from monarch_mcp_server.config import config
from monarch_mcp_server.store import ACCESS_TTL, CODE_TTL, get_store, new_secret


def allowed_scopes() -> list[str]:
    scopes = [config.oauth.read_scope]
    if not config.read_only:
        scopes.append(config.oauth.write_scope)
    return scopes


def clamp_scopes(requested: list[str] | None) -> list[str]:
    """Grant every scope this deployment offers, whatever was requested.

    Clients (e.g. Claude) request scopes from the protected-resource metadata,
    which the SDK limits to the globally required read scope, so honouring the
    request would leave connectors read-only even with writes enabled. Access
    is governed by READ_ONLY plus the consent screen, which lists these scopes.
    """
    return allowed_scopes()


class MonarchOAuthProvider:
    # -- clients (dynamic registration) --------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        raw = get_store().get_client(client_id)
        return OAuthClientInformationFull.model_validate_json(raw) if raw else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if not client_info.client_id:
            raise ValueError("client_id missing")
        get_store().save_client(client_info.client_id, client_info.model_dump_json())

    # -- authorization -------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Park the validated request and send the browser to our consent page."""
        if not config.oauth.public_url:
            raise AuthorizeError("server_error", "PUBLIC_URL is not configured")
        pid = get_store().save_pending(
            {
                "client_id": client.client_id,
                "client_name": client.client_name,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": (
                    params.redirect_uri_provided_explicitly
                ),
                "state": params.state,
                "scopes": clamp_scopes(params.scopes),
                "code_challenge": params.code_challenge,
                "resource": params.resource,
            }
        )
        return f"{config.oauth.public_url.rstrip('/')}/oauth/consent?req={pid}"

    def issue_code(self, pending: dict, user_id: str) -> str:
        code = new_secret()
        get_store().save_code(
            code,
            {
                "client_id": pending["client_id"],
                "scopes": pending["scopes"],
                "redirect_uri": pending["redirect_uri"],
                "redirect_uri_provided_explicitly": pending[
                    "redirect_uri_provided_explicitly"
                ],
                "code_challenge": pending["code_challenge"],
                "resource": pending["resource"],
                "subject": user_id,
            },
        )
        return code

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        data = get_store().get_code(authorization_code)
        if not data or data["client_id"] != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            expires_at=time.time() + CODE_TTL,
            **data,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        store = get_store()
        store.delete_code(authorization_code.code)  # single use
        return self._mint(
            authorization_code.subject or "",
            client.client_id or "",
            authorization_code.scopes,
            authorization_code.resource,
        )

    # -- refresh -------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        row = get_store().get_token(refresh_token, "refresh")
        if not row or row["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=row["client_id"],
            scopes=row["scopes"].split(),
            expires_at=int(row["expires"]),
            subject=row["user_id"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        store = get_store()
        row = store.get_token(refresh_token.token, "refresh")
        if not row:
            raise TokenError("invalid_grant", "refresh token is no longer valid")
        store.retire_pair(row["pair_id"])  # rotate; short grace for retries
        # Re-derive from current config (not the old grant) so tokens follow
        # READ_ONLY changes: enabling writes upgrades connectors on next refresh.
        return self._mint(
            row["user_id"],
            row["client_id"],
            clamp_scopes(scopes),
            row["resource"],
        )

    def _mint(
        self, user_id: str, client_id: str, scopes: list[str], resource: str | None
    ) -> OAuthToken:
        access, refresh = get_store().issue_tokens(
            user_id, client_id, scopes, resource
        )
        return OAuthToken(
            access_token=access,
            expires_in=ACCESS_TTL,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    # -- verification & revocation -------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        row = get_store().get_token(token, "access")
        if not row:
            return None
        return AccessToken(
            token=token,
            client_id=row["client_id"],
            scopes=row["scopes"].split(),
            expires_at=int(row["expires"]),
            resource=row["resource"],
            subject=row["user_id"],
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        store = get_store()
        for kind in ("access", "refresh"):
            row = store.get_token(token.token, kind)
            if row:
                store.revoke_pair(row["pair_id"])
