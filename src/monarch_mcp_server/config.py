"""Central runtime configuration, read once from environment variables.

Everything that controls transport, storage, and OAuth server behaviour is resolved here so the rest of the codebase has a single,
typed view of the deployment. Values are read at import time; the process is
expected to be restarted to pick up changes (as is normal for a container).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
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
    """Scopes and public origin for the built-in OAuth authorization server.

    This app is its own identity provider (see ``provider.py``): users sign up on
    the web UI, and MCP clients (e.g. Claude) obtain opaque bearer tokens via
    OAuth 2.1 + PKCE. There is no external IdP dependency.
    """

    read_scope: str
    write_scope: str
    public_url: str | None
    enabled: bool  # True for the HTTP transport; stdio is a local single-user mode

    @property
    def resource_id(self) -> str | None:
        """The MCP endpoint URL (resource indicator advertised in RFC 9728)."""
        if not self.public_url:
            return None
        return self.public_url.rstrip("/") + config_mcp_path()


def config_mcp_path() -> str:
    path = _clean("MCP_PATH") or "/mcp"
    return path if path.startswith("/") else "/" + path


@dataclass(frozen=True)
class Config:
    transport: str
    host: str
    port: int
    mcp_path: str
    session_store_path: Path
    read_only: bool
    rate_limit_per_minute: int
    data_dir: Path
    allow_signup: bool
    oauth: OAuthConfig

    @property
    def is_http(self) -> bool:
        return self.transport == "http"


def load_oauth(transport: str) -> OAuthConfig:
    return OAuthConfig(
        read_scope=_clean("REQUIRED_READ_SCOPE") or "monarch:read",
        write_scope=_clean("REQUIRED_WRITE_SCOPE") or "monarch:write",
        public_url=_clean("PUBLIC_URL"),
        enabled=transport == "http",
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

    # The origin serves the web UI; the MCP endpoint lives at a sub-path.
    mcp_path = config_mcp_path()
    if mcp_path == "/":
        raise ValueError("MCP_PATH must not be '/': the root serves the web UI")

    return Config(
        transport=transport,
        host=_clean("HOST") or "0.0.0.0",
        port=port,
        mcp_path=mcp_path,
        session_store_path=session_store,
        read_only=_bool("READ_ONLY", True),
        rate_limit_per_minute=rate_limit,
        data_dir=Path(_clean("DATA_DIR") or "/data"),
        # The first account (the admin) can always sign up; further sign-ups
        # need ALLOW_SIGNUP=true so a public URL is not an open registration.
        allow_signup=_bool("ALLOW_SIGNUP", False),
        oauth=load_oauth(transport),
    )


# Resolved once at import. Restart the process to apply changes.
config = load_config()
