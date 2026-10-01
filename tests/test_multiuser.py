"""Multi-user store tests + an end-to-end web/OAuth/MCP flow.

The e2e flow runs in a subprocess because ``config`` is resolved at import time
and the rest of the suite runs in stdio mode.
"""

import os
import subprocess
import sys
import textwrap
import time

import pytest

from monarch_mcp_server import store as store_mod
from monarch_mcp_server.store import Store, hash_password, verify_password


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    return Store(tmp_path)


def test_password_hashing_roundtrip():
    h = hash_password("correct horse battery")
    assert verify_password("correct horse battery", h)
    assert not verify_password("wrong", h)
    assert not verify_password("anything", None)
    assert not verify_password("x" * 1000, h)  # length-bounded


def test_first_user_is_admin_and_emails_unique(store):
    a = store.create_user("A@example.com", "passwordpassword")
    assert a and store.get_user(a)["is_admin"] == 1
    assert store.create_user("a@EXAMPLE.com", "otherpassword!!") is None
    b = store.create_user("b@example.com", "passwordpassword")
    assert b and store.get_user(b)["is_admin"] == 0


def test_authenticate(store):
    uid = store.create_user("a@example.com", "passwordpassword")
    assert store.authenticate("A@example.com ", "passwordpassword") == uid
    assert store.authenticate("a@example.com", "nope") is None
    assert store.authenticate("ghost@example.com", "passwordpassword") is None


def test_connections_are_encrypted_and_isolated(store, tmp_path):
    a = store.create_user("a@example.com", "passwordpassword")
    b = store.create_user("b@example.com", "passwordpassword")
    store.save_connection(a, {"token": "SECRET-A", "password": "pw-a"},
                          method="credentials", label="a@x")
    assert store.get_connection(a)["token"] == "SECRET-A"
    assert store.get_connection(b) is None
    raw = (tmp_path / "monarch.db").read_bytes()
    wal = tmp_path / "monarch.db-wal"
    raw += wal.read_bytes() if wal.exists() else b""
    assert b"SECRET-A" not in raw and b"pw-a" not in raw


def test_connection_unreadable_with_different_key(tmp_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "key-one")
    s1 = Store(tmp_path)
    uid = s1.create_user("a@example.com", "passwordpassword")
    s1.save_connection(uid, {"token": "t"}, method="token", label="x")
    monkeypatch.setenv("SECRET_KEY", "key-two")
    assert Store(tmp_path).get_connection(uid) is None


def test_tokens_hashed_expire_and_revoke(store):
    uid = store.create_user("a@example.com", "passwordpassword")
    access, refresh = store.issue_tokens(uid, "cid", ["monarch:read"], None)
    assert store.get_token(access, "access")["user_id"] == uid
    assert store.get_token(access, "refresh") is None  # kinds don't cross
    rows = store._q("SELECT token_hash FROM tokens")
    assert all(access not in r["token_hash"] for r in rows)  # only hashes stored
    store.revoke_pair(store.get_token(refresh, "refresh")["pair_id"])
    assert store.get_token(access, "access") is None


def test_default_token_lifetimes_are_long():
    assert store_mod.ACCESS_TTL >= 7 * 24 * 3600
    assert store_mod.REFRESH_TTL >= 365 * 24 * 3600


def test_retire_pair_keeps_refresh_briefly(store):
    uid = store.create_user("a@example.com", "passwordpassword")
    access, refresh = store.issue_tokens(uid, "cid", ["monarch:read"], None)
    pair = store.get_token(refresh, "refresh")["pair_id"]
    store.retire_pair(pair)
    assert store.get_token(access, "access") is None
    row = store.get_token(refresh, "refresh")
    assert row and row["expires"] <= time.time() + store_mod.REFRESH_GRACE + 1


def test_scopes_granted_follow_read_only(monkeypatch):
    import dataclasses
    from monarch_mcp_server import provider

    base = provider.config
    monkeypatch.setattr(provider, "config", dataclasses.replace(base, read_only=False))
    assert provider.clamp_scopes(["monarch:read"]) == ["monarch:read", "monarch:write"]
    assert provider.clamp_scopes(None) == ["monarch:read", "monarch:write"]
    monkeypatch.setattr(provider, "config", dataclasses.replace(base, read_only=True))
    assert provider.clamp_scopes(["monarch:read", "monarch:write"]) == ["monarch:read"]


def test_expired_session_rejected(store):
    sid, _ = store.create_session(None)
    assert store.get_session(sid)
    store._q("UPDATE web_sessions SET expires=?", (time.time() - 1,))
    assert store.get_session(sid) is None


def test_cascade_delete_user(store):
    uid = store.create_user("a@example.com", "passwordpassword")
    store.issue_tokens(uid, "cid", ["monarch:read"], None)
    store.save_connection(uid, {"token": "t"}, method="token", label="x")
    store._q("DELETE FROM users WHERE id=?", (uid,))
    assert store._q("SELECT * FROM tokens") == []
    assert store._q("SELECT * FROM connections") == []


E2E = textwrap.dedent(
    r'''
    import base64, dataclasses, hashlib, json, re, secrets
    from urllib.parse import parse_qs, urlparse
    from starlette.testclient import TestClient

    from monarch_mcp_server import client as mc
    class FakeClient:
        token = "monarch-token-1"
    async def fake_login(email, password, **kw):
        if password == "badbadbadbad":
            raise mc.MonarchAuthError("Monarch sign-in failed (test).")
        return FakeClient()
    mc.monarch_login = fake_login

    from monarch_mcp_server import web
    from monarch_mcp_server.app import build_http_app
    app = build_http_app()
    def csrf(html):
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    class NoLifespan(TestClient):
        # Only one client may run the app's lifespan (the MCP session manager).
        def __enter__(self): return self
        def __exit__(self, *a): return None

    def new_client():
        return NoLifespan(app, base_url="https://testserver", follow_redirects=False)

    with TestClient(app, base_url="https://testserver", follow_redirects=False) as c:
        r = c.get("/")
        assert r.status_code == 200 and "Sign in" in r.text and "Sign up" in r.text
        assert r.headers["x-frame-options"] == "DENY"
        assert "script" not in r.headers["content-security-policy"].replace("'none'", "")

        # signup requires CSRF
        assert c.post("/signup", data={"email": "a@example.com", "password": "passwordpassword"}).status_code == 400
        r = c.get("/signup"); tok = csrf(r.text)
        r = c.post("/signup", data={"csrf": tok, "email": "a@example.com", "password": "short"})
        assert r.status_code == 400 and "Password must be" in r.text
        r = c.post("/signup", data={"csrf": tok, "email": "a@example.com", "password": "passwordpassword"})
        assert r.status_code == 303 and r.headers["location"] == "/dashboard"

        r = c.get("/dashboard")
        assert r.status_code == 200 and "Not connected" in r.text
        assert "https://testserver/mcp" in r.text
        tok = csrf(r.text)

        r = c.post("/dashboard/connect", data={"csrf": tok, "email": "m@x.com", "password": "badbadbadbad"})
        assert "sign-in failed" in r.text
        r = c.post("/dashboard/connect", data={"csrf": tok, "email": "m@x.com", "password": "goodgoodgood", "keep": "1"})
        assert "Monarch connected" in r.text and "Healthy" in r.text
        assert "goodgoodgood" not in r.text and "monarch-token-1" not in r.text
        # forged CSRF is refused
        r = c.post("/dashboard/disconnect", data={"csrf": "nope"})
        assert "Session expired" in r.text

        # --- OAuth: DCR + PKCE ---
        cb = "https://claude.ai/api/mcp/auth_callback"
        r = c.post("/register", json={
            "redirect_uris": [cb], "client_name": "Claude",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"]})
        assert r.status_code == 201, r.text
        cid = r.json()["client_id"]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q = {"response_type": "code", "client_id": cid, "redirect_uri": cb,
             "code_challenge": challenge, "code_challenge_method": "S256",
             "state": "xyz", "resource": "https://testserver/mcp"}
        r = c.get("/authorize", params=q)
        assert r.status_code == 302 and "/oauth/consent?req=" in r.headers["location"], r.text
        consent = r.headers["location"]
        r = c.get(urlparse(consent).path + "?" + urlparse(consent).query)
        assert r.status_code == 200 and "Authorize Claude" in r.text
        assert "Unrecognized app" not in r.text  # claude.ai callback is known
        pid = re.search(r'name="req" value="([^"]+)"', r.text).group(1)
        # unauthenticated browser can't approve
        with new_client() as anon:
            assert anon.post("/oauth/consent", data={"csrf": "x", "req": pid, "action": "approve"}).headers["location"] == "/login"
            r2 = anon.get("/oauth/consent", params={"req": pid})
            assert r2.status_code == 303 and r2.headers["location"].startswith("/login?next=")
        r = c.post("/oauth/consent", data={"csrf": csrf(r.text), "req": pid, "action": "approve"})
        assert r.status_code == 302
        loc = urlparse(r.headers["location"])
        assert f"{loc.scheme}://{loc.netloc}{loc.path}" == cb
        qs = parse_qs(loc.query)
        assert qs["state"] == ["xyz"]; code = qs["code"][0]
        # pending request is single-use
        assert c.post("/oauth/consent", data={"csrf": tok, "req": pid, "action": "approve"}).status_code in (400, 200)

        tokreq = {"grant_type": "authorization_code", "code": code, "redirect_uri": cb,
                  "client_id": cid, "code_verifier": verifier}
        bad = c.post("/token", data={**tokreq, "code_verifier": "x" * 50})
        assert bad.status_code == 400
        r = c.post("/token", data=tokreq)
        assert r.status_code == 200, r.text
        tk = r.json(); access, refresh = tk["access_token"], tk["refresh_token"]
        assert c.post("/token", data=tokreq).status_code == 400  # code replay

        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"}}}
        h = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        def mcp_call(token):
            """POST /mcp through the lifespan-owning client, minus its cookies."""
            jar = list(c.cookies.jar)
            c.cookies.clear()
            try:
                hdrs = {**h, **({"Authorization": f"Bearer {token}"} if token else {})}
                return c.post("/mcp", json=init, headers=hdrs)
            finally:
                for ck in jar:
                    c.cookies.jar.set_cookie(ck)

        with new_client() as bare:  # no cookies, no token
            r = mcp_call(None)
            assert r.status_code == 401 and "resource_metadata" in r.headers["www-authenticate"]
            r = mcp_call("garbage")
            assert r.status_code == 401
            r = mcp_call(access)
            assert r.status_code == 200, r.text
            md = bare.get("/.well-known/oauth-protected-resource/mcp")
            assert md.status_code == 200 and md.json()["resource"].startswith("https://testserver/mcp")
            asm = bare.get("/.well-known/oauth-authorization-server").json()
            assert asm["registration_endpoint"].endswith("/register")

            # refresh rotates; old access token dies
            r = bare.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": cid})
            assert r.status_code == 200, r.text
            new_access = r.json()["access_token"]
            assert mcp_call(access).status_code == 401
            assert mcp_call(new_access).status_code == 200
            # old refresh token survives only a short grace window (lost-response retry)
            assert bare.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": cid}).status_code == 200
            from monarch_mcp_server.store import get_store, sha256
            import time as _t
            get_store()._q("UPDATE tokens SET expires=? WHERE token_hash=?", (_t.time() - 1, sha256(refresh)))
            assert bare.post("/token", data={"grant_type": "refresh_token", "refresh_token": refresh, "client_id": cid}).status_code == 400

        # revoke-all from the dashboard kills access
        r = c.get("/dashboard"); assert "connector session(s)" in r.text
        c.post("/dashboard/revoke", data={"csrf": csrf(r.text)})
        assert mcp_call(new_access).status_code == 401

        # sign out ends the session
        r = c.get("/dashboard"); c.post("/logout", data={"csrf": csrf(r.text)})
        assert c.get("/dashboard").headers["location"] == "/login"

    # --- registration closed after the first user (ALLOW_SIGNUP=false) ---
    with new_client() as c2:
        assert c2.get("/signup").status_code == 403
        assert "Registration is closed" in c2.get("/").text

    # --- second user is isolated; login throttling ---
    web.config = dataclasses.replace(web.config, allow_signup=True)
    with new_client() as c2:
        tok = csrf(c2.get("/signup").text)
        r = c2.post("/signup", data={"csrf": tok, "email": "b@example.com", "password": "passwordpassword"})
        assert r.status_code == 303
        assert "Not connected" in c2.get("/dashboard").text
    with new_client() as c3:
        tok = csrf(c3.get("/login").text)
        for _ in range(8):
            r = c3.post("/login", data={"csrf": tok, "email": "b@example.com", "password": "wrongwrongwrong"})
            assert "Incorrect email or password" in r.text
        r = c3.post("/login", data={"csrf": tok, "email": "b@example.com", "password": "passwordpassword"})
        assert "Too many attempts" in r.text
    print("E2E-OK")
    '''
)


def test_end_to_end_http_flow(tmp_path):
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "TRANSPORT": "http",
        "PUBLIC_URL": "https://testserver",
        "DATA_DIR": str(tmp_path),
        "SECRET_KEY": "e2e-test-secret",
        "ALLOW_SIGNUP": "false",
        "READ_ONLY": "true",
        "RATE_LIMIT_PER_MINUTE": "0",
    }
    proc = subprocess.run(
        [sys.executable, "-c", E2E], env=env, capture_output=True, text=True, timeout=120
    )
    assert "E2E-OK" in proc.stdout, proc.stdout[-2000:] + proc.stderr[-4000:]
