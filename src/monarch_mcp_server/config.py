"""Central runtime configuration, read once from environment variables.

Everything that controls transport, headless Monarch login, and OAuth resource
server behaviour is resolved here so the rest of the codebase has a single,
typed view of the deployment. Values are read at import time; the process is
expected to be restarted to pick up changes (as is normal for a container).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _clean(name: str) -> str | None:
    """Read an env var, returning None for unset/empty/whitespace values."""
    raw = os.getenv(name)
    if raw is None:
        return None
    raw = raw.strip()
    return raw or None


@dataclass(frozen=True)
class OAuthConfig:
    """OAuth 2.0 Resource Server settings (MCP auth spec, 2025-06-18).

    The server is a Resource Server only: it validates bearer JWTs issued by an
    external IdP and never runs an authorization flow itself.
    """

    issuer: str | None
    audience: str | None
    jwks_uri: str | None
    read_scope: str
    write_scope: str
    public_url: str | None

    @property
    def enabled(self) -> bool:
        """OAuth enforcement is active only when fully configured.

        Missing config means local/stdio development: we do not silently run an
        unauthenticated public server, but we also do not block stdio usage.
        """
        return bool(self.issuer and self.audience and self.jwks_uri)

    @property
    def resource_id(self) -> str | None:
        """The resource identifier advertised in RFC 9728 metadata and required
        as the JWT ``aud``. Defaults to the audience (this server's public URL)."""
        return self.audience or self.public_url


@dataclass(frozen=True)
class Config:
    transport: str
    host: str
    port: int
    session_store_path: Path
    read_only: bool
    rate_limit_per_minute: int
    oauth: OAuthConfig = field(default_factory=lambda: load_oauth())

    @property
    def is_http(self) -> bool:
        return self.transport == "http"


def load_oauth() -> OAuthConfig:
    return OAuthConfig(
        issuer=_clean("OAUTH_ISSUER"),
        audience=_clean("OAUTH_AUDIENCE") or _clean("PUBLIC_URL"),
        jwks_uri=_clean("OAUTH_JWKS_URI"),
        read_scope=_clean("REQUIRED_READ_SCOPE") or "monarch:read",
        write_scope=_clean("REQUIRED_WRITE_SCOPE") or "monarch:write",
        public_url=_clean("PUBLIC_URL"),
    )


def load_config() -> Config:
    transport = (_clean("TRANSPORT") or "stdio").lower()
    if transport not in {"stdio", "http"}:
        raise ValueError(f"TRANSPORT must be 'stdio' or 'http', got {transport!r}")

    try:
        port = int(_clean("PORT") or "8000")
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"PORT must be an integer: {exc}") from exc

    try:
        rate_limit = int(_clean("RATE_LIMIT_PER_MINUTE") or "120")
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"RATE_LIMIT_PER_MINUTE must be an integer: {exc}") from exc

    session_store = Path(_clean("SESSION_STORE_PATH") or "/data/monarch-session")

    return Config(
        transport=transport,
        host=_clean("HOST") or "0.0.0.0",
        port=port,
        session_store_path=session_store,
        read_only=_bool("READ_ONLY", True),
        rate_limit_per_minute=rate_limit,
        oauth=load_oauth(),
    )


# Resolved once at import. Restart the process to apply changes.
config = load_config()
