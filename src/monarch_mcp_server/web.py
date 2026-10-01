"""Server-rendered web UI: landing, sign in/up, dashboard, OAuth consent.

No JS framework and no build step -- plain HTML forms. Security model:
  * Sessions are random ids in an HttpOnly, SameSite=Lax (``__Host-`` + Secure
    over HTTPS) cookie; only the hash is stored. The id is rotated on login.
  * Every POST carries a per-session CSRF token (anonymous sessions get one too,
    so login/signup are covered).
  * All dynamic output goes through ``esc``; CSP forbids scripts entirely.
  * Login/signup are throttled per IP and per account.
"""

from __future__ import annotations

import asyncio
import hmac
import re
import time
from datetime import datetime, timezone
from html import escape as esc
from urllib.parse import quote, urlparse

from mcp.server.auth.provider import construct_redirect_uri
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from monarch_mcp_server import client as monarch_client
from monarch_mcp_server.config import config
from monarch_mcp_server.provider import MonarchOAuthProvider
from monarch_mcp_server.ratelimit import client_ip_of
from monarch_mcp_server.store import (
    MAX_PASSWORD_LEN,
    MIN_PASSWORD_LEN,
    SESSION_TTL,
    get_store,
    normalize_email,
)

_HTTPS = (config.oauth.public_url or "").startswith("https://")
_COOKIE = "__Host-session" if _HTTPS else "session"
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")
_NEXT_PREFIXES = ("/oauth/consent", "/dashboard")
# Client registration is open (Claude registers itself), so anyone can register a
# redirect URI. Flag anything outside the well-known clients on the consent page.
_KNOWN_REDIRECT_HOSTS = {"claude.ai", "claude.com", "localhost", "127.0.0.1"}

# ---------------------------------------------------------------------------
# Throttling (in-memory, per process)
# ---------------------------------------------------------------------------


class _Throttle:
    def __init__(self, limit: int, window: float) -> None:
        self.limit, self.window = limit, window
        self._hits: dict[str, list[float]] = {}

    def _prune(self, key: str) -> list[float]:
        if len(self._hits) > 10_000:
            self._hits.clear()
        cutoff = time.time() - self.window
        hits = [t for t in self._hits.get(key, []) if t > cutoff]
        self._hits[key] = hits
        return hits

    def blocked(self, key: str) -> bool:
        return len(self._prune(key)) >= self.limit

    def hit(self, key: str) -> None:
        self._prune(key).append(time.time())

    def reset(self, key: str) -> None:
        self._hits.pop(key, None)


_login_ip = _Throttle(20, 900)
_login_acct = _Throttle(8, 900)
_signup_ip = _Throttle(5, 3600)
_connect_user = _Throttle(10, 600)  # Monarch logins per user (it's an upstream call)

# ---------------------------------------------------------------------------
# Session / CSRF plumbing
# ---------------------------------------------------------------------------


class Ctx:
    """Resolves (or lazily creates) the browser session for one request."""

    def __init__(self, request: Request) -> None:
        self.request = request
        store = get_store()
        self.sid = request.cookies.get(_COOKIE)
        row = store.get_session(self.sid)
        self._fresh = False
        if row is None:
            self.sid, csrf = store.create_session(None)
            self.csrf, self.user_id, self._fresh = csrf, None, True
        else:
            self.csrf, self.user_id = row["csrf"], row["user_id"]
        self.user = store.get_user(self.user_id) if self.user_id else None
        if self.user_id and not self.user:
            self.user_id = None

    def attach(self, response: Response) -> Response:
        if self._fresh:
            self.set_cookie(response, self.sid, 3600)
        return response

    @staticmethod
    def set_cookie(response: Response, sid: str, max_age: int) -> None:
        response.set_cookie(
            _COOKIE, sid, max_age=max_age, httponly=True, secure=_HTTPS,
            samesite="lax", path="/",
        )

    def csrf_ok(self, supplied: str | None) -> bool:
        return bool(supplied) and hmac.compare_digest(supplied or "", self.csrf)

    def login(self, response: Response, user_id: str) -> None:
        """Rotate to a fresh authenticated session (prevents fixation)."""
        store = get_store()
        store.delete_session(self.sid)
        sid, _ = store.create_session(user_id)
        self.set_cookie(response, sid, SESSION_TTL)
        self._fresh = False

    def logout(self, response: Response) -> None:
        get_store().delete_session(self.sid)
        response.delete_cookie(_COOKIE, path="/")


def _redirect(url: str, ctx: Ctx | None = None) -> Response:
    resp = RedirectResponse(url, status_code=303)
    return ctx.attach(resp) if ctx else resp


def _safe_next(value: str | None) -> str:
    if (
        value
        and value.startswith(_NEXT_PREFIXES)
        and "\\" not in value
        and "//" not in value
    ):
        return value
    return "/dashboard"


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_CSS = """
:root{color-scheme:light dark;--bg:#f6f7f9;--card:#fff;--fg:#14171c;--mut:#5d6673;
--line:#e2e6ec;--acc:#16a34a;--acc2:#15803d;--bad:#dc2626;--warn:#d97706}
@media(prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#171b22;--fg:#e8ebf0;
--mut:#97a1b0;--line:#272d37}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--acc)}main{max-width:760px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;
max-width:760px;margin:0 auto;padding:20px 16px 0}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:1.15rem;
color:inherit;text-decoration:none}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;
padding:20px;margin:16px 0}
h1{font-size:1.9rem;line-height:1.2;margin:.2em 0}h2{font-size:1.1rem;margin:0 0 12px}
p{margin:.5em 0}.mut{color:var(--mut)}.hero{text-align:center;padding:48px 0 16px}
.hero p{max-width:520px;margin:12px auto}
label{display:block;font-size:.88rem;font-weight:600;margin:12px 0 4px}
input[type=text],input[type=email],input[type=password]{width:100%;padding:10px 12px;
border-radius:9px;border:1px solid var(--line);background:var(--bg);color:var(--fg);
font:inherit}
.btn{display:inline-block;border:0;border-radius:9px;padding:10px 18px;font:inherit;
font-weight:600;cursor:pointer;background:var(--acc);color:#fff;text-decoration:none}
.btn:hover{background:var(--acc2)}.btn.sec{background:transparent;color:var(--fg);
border:1px solid var(--line)}.btn.bad{background:var(--bad)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:14px}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:.82rem;
font-weight:700;color:#fff}.ok{background:var(--acc)}.err{background:var(--bad)}
.none{background:var(--mut)}.flash{border-left:4px solid var(--acc);padding:10px 14px;
background:var(--card);border-radius:8px;margin:16px 0}.flash.err{border-color:var(--bad);
color:inherit;background:var(--card)}
code{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:2px 6px;
word-break:break-all}pre{background:var(--bg);border:1px solid var(--line);
border-radius:9px;padding:10px;overflow:auto}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:12px 0}
dt{color:var(--mut)}dd{margin:0;word-break:break-word}
details{margin-top:14px}summary{cursor:pointer;font-weight:600}
ol{padding-left:20px}li{margin:6px 0}
"""

_LOGO = (
    '<svg width="34" height="34" viewBox="0 0 34 34" role="img" aria-label="Monarch MCP">'
    '<rect width="34" height="34" rx="9" fill="#16a34a"/>'
    '<path d="M7 25V10l10 10 10-10v15" fill="none" stroke="#fff" stroke-width="3" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def _page(
    ctx: Ctx, title: str, body: str, *, status: int = 200, nav: bool = True
) -> HTMLResponse:
    right = ""
    if nav and ctx.user:
        right = (
            f'<form method="post" action="/logout" style="margin:0">'
            f'<input type="hidden" name="csrf" value="{esc(ctx.csrf)}">'
            f'<span class="mut">{esc(ctx.user["email"])}</span> &nbsp;'
            f'<button class="btn sec" type="submit">Sign out</button></form>'
        )
    html = (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{esc(title)} · Monarch MCP</title>"
        '<link rel="icon" href="/favicon.ico">'
        f"<style>{_CSS}</style></head><body>"
        f'<header><a class="brand" href="/">{_LOGO}<span>Monarch MCP</span></a>'
        f"{right}</header><main>{body}</main></body></html>"
    )
    return ctx.attach(HTMLResponse(html, status_code=status))


def _flash(msg: str | None, bad: bool = False) -> str:
    if not msg:
        return ""
    return f'<div class="flash{" err" if bad else ""}" role="status">{esc(msg)}</div>'


def _csrf(ctx: Ctx) -> str:
    return f'<input type="hidden" name="csrf" value="{esc(ctx.csrf)}">'


def _fmt_ts(ts: float | None) -> str:
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _signup_open() -> bool:
    return config.allow_signup or get_store().user_count() == 0


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------


async def landing(request: Request) -> Response:
    ctx = Ctx(request)
    if ctx.user:
        return _redirect("/dashboard", ctx)
    signup = (
        '<a class="btn" href="/signup">Sign up</a>'
        if _signup_open()
        else '<span class="mut">Registration is closed.</span>'
    )
    return _page(
        ctx,
        "Welcome",
        f"""<section class="hero">
<h1>Your Monarch Money data,<br>available to your AI assistant.</h1>
<p class="mut">Connect your Monarch account once, then link this server to Claude
as a connector. Your credentials are encrypted at rest and never shown to the model.</p>
<div class="row" style="justify-content:center">
<a class="btn" href="/login">Sign in</a>{signup}</div></section>
<div class="card"><h2>How it works</h2><ol>
<li>Create an account here.</li><li>Connect your Monarch account.</li>
<li>Add this server as a custom connector in Claude and approve access.</li></ol></div>""",
        nav=False,
    )


def _auth_form(ctx: Ctx, kind: str, error: str | None, nxt: str = "", email: str = "") -> HTMLResponse:
    signup = kind == "signup"
    title = "Create account" if signup else "Sign in"
    hint = (
        f'<p class="mut">At least {MIN_PASSWORD_LEN} characters.</p>' if signup else ""
    )
    alt = (
        '<p class="mut">Already registered? <a href="/login">Sign in</a></p>'
        if signup
        else (
            '<p class="mut">New here? <a href="/signup">Create an account</a></p>'
            if _signup_open()
            else ""
        )
    )
    body = f"""<div class="card" style="max-width:420px;margin:32px auto">
<h2>{title}</h2>{_flash(error, True)}
<form method="post" action="/{kind}">{_csrf(ctx)}
<input type="hidden" name="next" value="{esc(nxt)}">
<label for=email>Email</label>
<input id=email name=email type=email value="{esc(email)}" autocomplete=email required maxlength=254>
<label for=pw>Password</label>
<input id=pw name=password type=password required maxlength={MAX_PASSWORD_LEN}
 autocomplete="{'new-password' if signup else 'current-password'}">
{hint}<div class="row"><button class="btn" type="submit">{title}</button></div></form>
{alt}</div>"""
    return _page(ctx, title, body, status=400 if error else 200, nav=False)


async def _read_form(request: Request, ctx: Ctx) -> dict[str, str] | None:
    """Parse a bounded urlencoded form and verify CSRF; None on failure."""
    if int(request.headers.get("content-length") or 0) > 16_384:
        return None
    form = await request.form()
    data = {k: v for k, v in form.items() if isinstance(v, str)}
    return data if ctx.csrf_ok(data.get("csrf")) else None


async def login_page(request: Request) -> Response:
    ctx = Ctx(request)
    nxt = _safe_next(request.query_params.get("next")) if request.query_params.get("next") else ""
    if ctx.user:
        return _redirect(nxt or "/dashboard", ctx)
    return _auth_form(ctx, "login", None, nxt)


async def login_submit(request: Request) -> Response:
    ctx = Ctx(request)
    form = await _read_form(request, ctx)
    if form is None:
        return _auth_form(ctx, "login", "Session expired. Please try again.")
    email = normalize_email(form.get("email", ""))
    ip, nxt = client_ip_of(request), _safe_next(form.get("next")) if form.get("next") else ""
    if _login_ip.blocked(ip) or _login_acct.blocked(email):
        return _auth_form(ctx, "login", "Too many attempts. Try again in a few minutes.", nxt, email)
    user_id = await asyncio.to_thread(
        get_store().authenticate, email, form.get("password", "")
    )
    if not user_id:
        _login_ip.hit(ip)
        _login_acct.hit(email)
        return _auth_form(ctx, "login", "Incorrect email or password.", nxt, email)
    _login_acct.reset(email)
    resp = _redirect(nxt or "/dashboard")
    ctx.login(resp, user_id)
    return resp


async def signup_page(request: Request) -> Response:
    ctx = Ctx(request)
    if ctx.user:
        return _redirect("/dashboard", ctx)
    if not _signup_open():
        return _page(ctx, "Registration closed", '<div class="card"><h2>Registration is closed</h2>'
                     '<p class="mut">Ask the administrator to enable sign-ups.</p></div>',
                     status=403, nav=False)
    return _auth_form(ctx, "signup", None)


async def signup_submit(request: Request) -> Response:
    ctx = Ctx(request)
    form = await _read_form(request, ctx)
    if form is None:
        return _auth_form(ctx, "signup", "Session expired. Please try again.")
    if not _signup_open():
        return _redirect("/signup", ctx)
    email, pw = normalize_email(form.get("email", "")), form.get("password", "")
    ip = client_ip_of(request)
    if _signup_ip.blocked(ip):
        return _auth_form(ctx, "signup", "Too many sign-ups from your network. Try later.", "", email)
    if not _EMAIL_RE.match(email) or len(email) > 254:
        return _auth_form(ctx, "signup", "Enter a valid email address.", "", email)
    if not (MIN_PASSWORD_LEN <= len(pw) <= MAX_PASSWORD_LEN):
        return _auth_form(ctx, "signup", f"Password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters.", "", email)
    _signup_ip.hit(ip)
    user_id = await asyncio.to_thread(get_store().create_user, email, pw)
    if not user_id:
        # Generic wording: don't confirm which emails are registered.
        return _auth_form(ctx, "signup", "Could not create that account. Try signing in.", "", email)
    resp = _redirect("/dashboard")
    ctx.login(resp, user_id)
    return resp


async def logout(request: Request) -> Response:
    ctx = Ctx(request)
    form = await _read_form(request, ctx)
    resp = _redirect("/")
    if form is not None:
        ctx.logout(resp)
    return resp


# -- dashboard ----------------------------------------------------------------


def _status_pill(meta) -> str:
    if meta is None:
        return '<span class="pill none">Not connected</span>'
    if meta["status"] == "ok":
        return '<span class="pill ok">Healthy</span>'
    return '<span class="pill err">Needs attention</span>'


def _dashboard(ctx: Ctx, msg: str | None = None, bad: bool = False) -> HTMLResponse:
    store = get_store()
    uid = ctx.user_id
    meta = store.connection_meta(uid)
    apps = store.authorized_client_count(uid)
    mcp_url = config.oauth.resource_id or "(PUBLIC_URL is not configured)"

    if meta:
        method = "Email + password (auto-renewing)" if meta["method"] == "credentials" else "Session token (manual renewal)"
        err = (
            f'<dt>Last error</dt><dd>{esc(meta["last_error"])}</dd>'
            if meta["last_error"] else ""
        )
        detail = (
            f'<dl><dt>Account</dt><dd>{esc(meta["label"] or "—")}</dd>'
            f"<dt>Method</dt><dd>{esc(method)}</dd>"
            f'<dt>Last checked</dt><dd>{_fmt_ts(meta["last_checked"])}</dd>{err}</dl>'
            f'<div class="row"><form method="post" action="/dashboard/test">{_csrf(ctx)}'
            '<button class="btn" type="submit">Test connection</button></form>'
            f'<form method="post" action="/dashboard/disconnect">{_csrf(ctx)}'
            '<button class="btn bad" type="submit">Disconnect</button></form></div>'
        )
    else:
        detail = '<p class="mut">Connect your Monarch account to get started.</p>'

    connect_forms = f"""<details{' open' if not meta else ''}><summary>{'Update connection' if meta else 'Connect Monarch'}</summary>
<form method="post" action="/dashboard/connect">{_csrf(ctx)}
<label for=me>Monarch email</label><input id=me name=email type=email required maxlength=254 autocomplete=off>
<label for=mp>Monarch password</label><input id=mp name=password type=password required maxlength=256 autocomplete=off>
<label for=ms>Authenticator secret <span class="mut">(if MFA is on; enables automatic renewal)</span></label>
<input id=ms name=mfa_secret type=text maxlength=128 autocomplete=off placeholder="Base32 key from Monarch's MFA setup">
<label for=mc>Or a current MFA code <span class="mut">(one-time; no auto-renewal)</span></label>
<input id=mc name=mfa_code type=text maxlength=12 inputmode=numeric autocomplete=off>
<label><input type=checkbox name=keep value=1 checked> Keep me connected: store my credentials encrypted so the server can renew an expired session</label>
<div class="row"><button class="btn" type="submit">Save connection</button></div></form>
<details><summary>Sign in with a session token instead (SSO users)</summary>
<form method="post" action="/dashboard/connect-token">{_csrf(ctx)}
<p class="mut">From app.monarchmoney.com → DevTools → Application → Local Storage → <code>token</code>. It expires, and you'll need to paste a new one.</p>
<label for=mt>Session token</label><input id=mt name=token type=password required maxlength=4096 autocomplete=off>
<div class="row"><button class="btn sec" type="submit">Save token</button></div></form></details></details>"""

    write = "disabled (read-only mode)" if config.read_only else "enabled"
    apps_block = (
        f'<p>{apps} connector session(s) currently authorized.</p>'
        f'<form method="post" action="/dashboard/revoke">{_csrf(ctx)}'
        '<button class="btn sec" type="submit">Revoke all connector access</button></form>'
        if apps else '<p class="mut">No connector has been authorized yet.</p>'
    )
    body = f"""{_flash(msg, bad)}
<div class="card"><h2>Monarch connection &nbsp;{_status_pill(meta)}</h2>{detail}{connect_forms}</div>
<div class="card"><h2>Link to Claude</h2><ol>
<li>In Claude, open <b>Settings → Connectors → Add custom connector</b>.</li>
<li>Name it <b>Monarch</b> and paste this URL (leave client ID/secret blank):<br><code>{esc(mcp_url)}</code></li>
<li>Click <b>Connect</b>. You'll return to this site to sign in and <b>Approve</b>.</li>
<li>Ask Claude something like “What’s my net worth?”</li></ol>
<p class="mut">Claude Code: <code>claude mcp add --transport http monarch {esc(mcp_url)}</code></p>
{apps_block}</div>
<div class="card"><h2>Server</h2><dl><dt>Status</dt><dd><span class="pill ok">Online</span></dd>
<dt>Write tools</dt><dd>{write}</dd></dl></div>"""
    return _page(ctx, "Dashboard", body)


def _need_user(ctx: Ctx) -> Response | None:
    return None if ctx.user else _redirect("/login", ctx)


async def dashboard(request: Request) -> Response:
    ctx = Ctx(request)
    return _need_user(ctx) or _dashboard(ctx)


async def _post_action(request: Request):
    ctx = Ctx(request)
    if (r := _need_user(ctx)) is not None:
        return ctx, None, r
    form = await _read_form(request, ctx)
    if form is None:
        return ctx, None, _dashboard(ctx, "Session expired. Please try again.", True)
    return ctx, form, None


async def connect(request: Request) -> Response:
    ctx, form, early = await _post_action(request)
    if early is not None:
        return early
    uid = ctx.user_id
    if _connect_user.blocked(uid):
        return _dashboard(ctx, "Too many connection attempts. Wait a few minutes.", True)
    _connect_user.hit(uid)
    email, password = form.get("email", "").strip(), form.get("password", "")
    secret = form.get("mfa_secret", "").strip().replace(" ", "")
    try:
        client = await asyncio.wait_for(
            monarch_client.monarch_login(
                email, password, mfa_secret=secret or None,
                mfa_code=form.get("mfa_code", ""),
            ),
            timeout=45,
        )
    except (monarch_client.MonarchAuthError, asyncio.TimeoutError) as exc:
        msg = str(exc) or "Monarch did not respond in time."
        return _dashboard(ctx, msg, True)
    data = {"token": client.token}
    if form.get("keep"):
        data.update(email=email, password=password)
        if secret:
            data["mfa_secret"] = secret
    get_store().save_connection(
        uid, data, method="credentials" if form.get("keep") else "token", label=email
    )
    monarch_client.clear_user_client(uid)
    return _dashboard(ctx, "Monarch connected.")


async def connect_token(request: Request) -> Response:
    ctx, form, early = await _post_action(request)
    if early is not None:
        return early
    uid, token = ctx.user_id, form.get("token", "").strip()
    if _connect_user.blocked(uid):
        return _dashboard(ctx, "Too many connection attempts. Wait a few minutes.", True)
    _connect_user.hit(uid)
    client = monarch_client.MonarchMoney(token=token)
    try:
        ok = bool(token) and await asyncio.wait_for(
            monarch_client.is_session_valid(client), timeout=30
        )
    except asyncio.TimeoutError:
        ok = False
    if not ok:
        return _dashboard(ctx, "Monarch rejected that token.", True)
    get_store().save_connection(uid, {"token": token}, method="token", label="session token")
    monarch_client.clear_user_client(uid)
    return _dashboard(ctx, "Monarch connected.")


async def test_connection(request: Request) -> Response:
    ctx, _form, early = await _post_action(request)
    if early is not None:
        return early
    if get_store().connection_meta(ctx.user_id) is None:
        return _dashboard(ctx, "Nothing to test yet.", True)
    ok, err = await asyncio.wait_for(
        monarch_client.check_user_health(ctx.user_id), timeout=60
    )
    return _dashboard(ctx, "Connection is healthy." if ok else (err or "Check failed."), not ok)


async def disconnect(request: Request) -> Response:
    ctx, _form, early = await _post_action(request)
    if early is not None:
        return early
    get_store().delete_connection(ctx.user_id)
    monarch_client.clear_user_client(ctx.user_id)
    return _dashboard(ctx, "Monarch disconnected and credentials deleted.")


async def revoke(request: Request) -> Response:
    ctx, _form, early = await _post_action(request)
    if early is not None:
        return early
    get_store().revoke_user_tokens(ctx.user_id)
    return _dashboard(ctx, "All connector access revoked.")


# -- OAuth consent ------------------------------------------------------------

_provider = MonarchOAuthProvider()


def _consent_error(ctx: Ctx) -> HTMLResponse:
    return _page(ctx, "Request expired", '<div class="card"><h2>This request has expired</h2>'
                 '<p class="mut">Go back to Claude and start the connection again.</p></div>',
                 status=400, nav=False)


async def consent_page(request: Request) -> Response:
    ctx = Ctx(request)
    pid = request.query_params.get("req", "")
    pending = get_store().get_pending(pid)
    if not pending:
        return _consent_error(ctx)
    if not ctx.user:
        return _redirect(f"/login?next={quote('/oauth/consent?req=' + pid)}", ctx)
    host = urlparse(pending["redirect_uri"]).netloc
    hostname = urlparse(pending["redirect_uri"]).hostname or ""
    unknown = (
        ""
        if hostname in _KNOWN_REDIRECT_HOSTS
        else _flash(
            f"Unrecognized app: it will send your access to {host}. Only approve if "
            "you started this connection yourself and trust that site.",
            True,
        )
    )
    scopes = "".join(f"<li><code>{esc(s)}</code></li>" for s in pending["scopes"])
    warn = (
        "" if get_store().connection_meta(ctx.user_id)
        else _flash("You haven't connected Monarch yet. You can approve now and connect from the dashboard.")
    )
    body = f"""<div class="card" style="max-width:520px;margin:32px auto">
<h2>Authorize {esc(pending.get("client_name") or "this app")}?</h2>{unknown}{warn}
<p>This app will be able to use your connected Monarch data with these permissions:</p>
<ul>{scopes}</ul><p class="mut">It will return to <code>{esc(host)}</code>. Only approve if you started this from your own AI client.</p>
<form method="post" action="/oauth/consent">{_csrf(ctx)}<input type="hidden" name="req" value="{esc(pid)}">
<div class="row"><button class="btn" name="action" value="approve" type="submit">Approve</button>
<button class="btn sec" name="action" value="deny" type="submit">Deny</button></div></form></div>"""
    return _page(ctx, "Authorize", body)


async def consent_submit(request: Request) -> Response:
    ctx = Ctx(request)
    if not ctx.user:
        return _redirect("/login", ctx)
    form = await _read_form(request, ctx)
    if form is None:
        return _consent_error(ctx)
    store = get_store()
    pid = form.get("req", "")
    pending = store.get_pending(pid)
    if not pending:
        return _consent_error(ctx)
    store.delete_pending(pid)  # one decision per request
    if form.get("action") != "approve":
        url = construct_redirect_uri(
            pending["redirect_uri"], error="access_denied", state=pending["state"]
        )
    else:
        code = _provider.issue_code(pending, ctx.user_id)
        url = construct_redirect_uri(pending["redirect_uri"], code=code, state=pending["state"])
    return RedirectResponse(url, status_code=302)


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def register_routes(mcp) -> None:
    routes = [
        ("/", landing, "GET"), ("/login", login_page, "GET"),
        ("/login", login_submit, "POST"), ("/signup", signup_page, "GET"),
        ("/signup", signup_submit, "POST"), ("/logout", logout, "POST"),
        ("/dashboard", dashboard, "GET"), ("/dashboard/connect", connect, "POST"),
        ("/dashboard/connect-token", connect_token, "POST"),
        ("/dashboard/test", test_connection, "POST"),
        ("/dashboard/disconnect", disconnect, "POST"),
        ("/dashboard/revoke", revoke, "POST"),
        ("/oauth/consent", consent_page, "GET"),
        ("/oauth/consent", consent_submit, "POST"),
    ]
    for path, handler, method in routes:
        mcp.custom_route(path, methods=[method])(handler)


class SecurityHeaders:
    """ASGI middleware adding hardening headers to every response."""

    def __init__(self, app) -> None:
        self.app = app
        self._headers = [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (
                b"content-security-policy",
                b"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
                b"base-uri 'none'; frame-ancestors 'none'",
            ),
        ]
        if _HTTPS:
            self._headers.append(
                (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
            )

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def wrapped(message):
            if message["type"] == "http.response.start":
                present = {k.lower() for k, _ in message["headers"]}
                message["headers"] = list(message["headers"]) + [
                    h for h in self._headers if h[0] not in present
                ]
            await send(message)

        await self.app(scope, receive, wrapped)
