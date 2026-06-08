"""Tests for read-only mode and per-tool write-scope enforcement."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import monarch_mcp_server.security as security
from monarch_mcp_server.security import WriteScopeRequired, write_tool


# Regression guard for the security audit (C1/C2): tools that mutate server or
# Monarch state must be on the WRITE path, so they are unregistered under the
# default READ_ONLY=true and otherwise require monarch:write. If someone adds a
# mutating tool with a bare @mcp.tool(), this test should start failing once the
# tool name is added here.
MUST_BE_WRITE_GATED = {
    # session/auth state mutations
    "monarch_login",
    "monarch_login_with_token",
    "monarch_logout",
    # institution-side mutation / amplification
    "refresh_accounts",
    # representative data mutations
    "set_budget_amount",
    "create_transaction",
    "delete_transaction",
}


def test_mutating_tools_unregistered_in_read_only():
    """With the default READ_ONLY=true, no mutating tool is exposed."""
    import monarch_mcp_server.app as app

    registered = {t.name for t in app.mcp._tool_manager.list_tools()}
    leaked = MUST_BE_WRITE_GATED & registered
    assert not leaked, f"mutating tools exposed on the read path: {sorted(leaked)}"


@pytest.fixture
def fake_mcp(monkeypatch):
    """Replace the real FastMCP so registration is observable and isolated."""
    m = MagicMock()
    # mcp.tool() returns a decorator that returns its argument unchanged.
    m.tool.return_value = lambda fn: fn
    monkeypatch.setattr(security, "_mcp", lambda: m)
    return m


def _set_config(monkeypatch, *, read_only, oauth_enabled):
    cfg = SimpleNamespace(
        read_only=read_only,
        oauth=SimpleNamespace(enabled=oauth_enabled, write_scope="monarch:write"),
    )
    monkeypatch.setattr(security, "config", cfg)
    return cfg


def test_read_only_does_not_register(fake_mcp, monkeypatch):
    _set_config(monkeypatch, read_only=True, oauth_enabled=True)

    @write_tool()
    async def mutate() -> str:
        return "ok"

    fake_mcp.tool.assert_not_called()


def test_write_enabled_registers(fake_mcp, monkeypatch):
    _set_config(monkeypatch, read_only=False, oauth_enabled=False)

    @write_tool()
    async def mutate() -> str:
        return "ok"

    fake_mcp.tool.assert_called_once()


@pytest.mark.asyncio
async def test_write_without_token_rejected(fake_mcp, monkeypatch):
    _set_config(monkeypatch, read_only=False, oauth_enabled=True)
    monkeypatch.setattr(security, "get_access_token", lambda: None)

    @write_tool()
    async def mutate() -> str:
        return "ok"

    with pytest.raises(WriteScopeRequired):
        await mutate()


@pytest.mark.asyncio
async def test_write_missing_scope_rejected(fake_mcp, monkeypatch):
    _set_config(monkeypatch, read_only=False, oauth_enabled=True)
    token = SimpleNamespace(scopes=["monarch:read"])
    monkeypatch.setattr(security, "get_access_token", lambda: token)

    @write_tool()
    async def mutate() -> str:
        return "ok"

    with pytest.raises(WriteScopeRequired):
        await mutate()


@pytest.mark.asyncio
async def test_write_with_scope_allowed(fake_mcp, monkeypatch):
    _set_config(monkeypatch, read_only=False, oauth_enabled=True)
    token = SimpleNamespace(scopes=["monarch:read", "monarch:write"])
    monkeypatch.setattr(security, "get_access_token", lambda: token)

    @write_tool()
    async def mutate() -> str:
        return "ok"

    assert await mutate() == "ok"


@pytest.mark.asyncio
async def test_oauth_disabled_skips_scope_check(fake_mcp, monkeypatch):
    _set_config(monkeypatch, read_only=False, oauth_enabled=False)

    @write_tool()
    async def mutate() -> str:
        return "ok"

    assert await mutate() == "ok"
