"""SQLite persistence for the multi-user server.

Holds users, web sessions, each user's (encrypted) Monarch connection, and the
built-in OAuth server's clients / codes / tokens. Stdlib ``sqlite3`` only; the
workload is tiny so a single locked connection is plenty.

Secrets handling:
  * Passwords: scrypt with a per-user salt (never reversible).
  * Monarch credentials/tokens: Fernet-encrypted at rest. The key comes from
    ``SECRET_KEY`` or is generated once into ``DATA_DIR/secret.key`` (mode 0600).
  * Bearer/refresh/auth-code/session values: only their SHA-256 is stored, so a
    leaked database cannot be replayed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 256  # bound scrypt work an attacker can request
SESSION_TTL = 7 * 24 * 3600
ANON_SESSION_TTL = 3600
def _ttl(name: str, default: int) -> int:
    try:
        return max(60, int(os.getenv(name) or default))
    except ValueError:
        return default


# Long-lived on purpose: connectors should not force a re-login. Refresh tokens
# are sliding (every refresh issues a fresh full-length one), so an in-use
# connection effectively never expires; revocation is always available.
ACCESS_TTL = _ttl("ACCESS_TOKEN_TTL_SECONDS", 7 * 24 * 3600)
REFRESH_TTL = _ttl("REFRESH_TOKEN_TTL_SECONDS", 365 * 24 * 3600)
REFRESH_GRACE = 300  # old refresh token stays usable briefly after rotation
CODE_TTL = 300
PENDING_TTL = 600
MAX_CLIENTS = 1000  # cap open dynamic client registration

_SCRYPT = {"n": 2**14, "r": 8, "p": 1}


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_secret(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return "scrypt${n}${r}${p}${salt}${dk}".format(
        **_SCRYPT,
        salt=base64.b64encode(salt).decode(),
        dk=base64.b64encode(dk).decode(),
    )


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time check. A ``None`` hash still burns an scrypt so unknown
    accounts are indistinguishable from wrong passwords by timing."""
    if len(password) > MAX_PASSWORD_LEN:
        return False
    if not stored:
        hashlib.scrypt(password.encode(), salt=b"\0" * 16, dklen=32, **_SCRYPT)
        return False
    try:
        _, n, r, p, salt, dk = stored.split("$")
        expected = base64.b64decode(dk)
        actual = hashlib.scrypt(
            password.encode(),
            salt=base64.b64decode(salt),
            dklen=len(expected),
            n=int(n),
            r=int(r),
            p=int(p),
        )
    except Exception:
        return False
    return hmac.compare_digest(actual, expected)


def _load_fernet(data_dir: Path) -> Fernet:
    secret = (os.getenv("SECRET_KEY") or "").strip()
    if secret:
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
        return Fernet(key)
    key_file = data_dir / "secret.key"
    if key_file.is_file():
        return Fernet(key_file.read_bytes().strip())
    key = Fernet.generate_key()
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return Fernet(key)


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    pw_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS web_sessions (
    sid_hash TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    csrf TEXT NOT NULL,
    expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS connections (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    blob BLOB NOT NULL,
    method TEXT NOT NULL,
    label TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    last_checked REAL,
    last_error TEXT,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_auth (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    pair_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    scopes TEXT NOT NULL,
    resource TEXT,
    expires REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS tokens_pair ON tokens(pair_id);
"""


class Store:
    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            data_dir.chmod(0o700)
        except OSError:  # pragma: no cover - e.g. Windows
            pass
        self._fernet = _load_fernet(data_dir)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(
            data_dir / "monarch.db", check_same_thread=False, isolation_level=None
        )
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(_SCHEMA)

    # -- low-level -----------------------------------------------------------

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _one(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        rows = self._q(sql, args)
        return rows[0] if rows else None

    def _purge(self) -> None:
        now = time.time()
        for table in ("web_sessions", "pending_auth", "auth_codes", "tokens"):
            self._q(f"DELETE FROM {table} WHERE expires < ?", (now,))

    # -- users ---------------------------------------------------------------

    def user_count(self) -> int:
        return self._one("SELECT COUNT(*) AS n FROM users")["n"]

    def create_user(self, email: str, password: str) -> str | None:
        """Create a user; the very first one is the admin. None if email taken."""
        user_id = new_secret(12)
        with self._lock:
            first = self.user_count() == 0
            try:
                self._q(
                    "INSERT INTO users(id,email,pw_hash,is_admin,created_at) "
                    "VALUES(?,?,?,?,?)",
                    (
                        user_id,
                        normalize_email(email),
                        hash_password(password),
                        int(first),
                        time.time(),
                    ),
                )
            except sqlite3.IntegrityError:
                return None
        return user_id

    def authenticate(self, email: str, password: str) -> str | None:
        row = self._one(
            "SELECT id, pw_hash FROM users WHERE email=?", (normalize_email(email),)
        )
        ok = verify_password(password, row["pw_hash"] if row else None)
        return row["id"] if row and ok else None

    def get_user(self, user_id: str) -> sqlite3.Row | None:
        return self._one("SELECT * FROM users WHERE id=?", (user_id,))

    # -- web sessions --------------------------------------------------------

    def create_session(self, user_id: str | None = None) -> tuple[str, str]:
        """Return ``(sid, csrf)``. Only the hash of ``sid`` is stored."""
        sid, csrf = new_secret(), new_secret(16)
        ttl = SESSION_TTL if user_id else ANON_SESSION_TTL
        self._purge()
        self._q(
            "INSERT INTO web_sessions(sid_hash,user_id,csrf,expires) VALUES(?,?,?,?)",
            (sha256(sid), user_id, csrf, time.time() + ttl),
        )
        return sid, csrf

    def get_session(self, sid: str | None) -> sqlite3.Row | None:
        if not sid:
            return None
        return self._one(
            "SELECT * FROM web_sessions WHERE sid_hash=? AND expires>?",
            (sha256(sid), time.time()),
        )

    def delete_session(self, sid: str | None) -> None:
        if sid:
            self._q("DELETE FROM web_sessions WHERE sid_hash=?", (sha256(sid),))

    # -- monarch connection --------------------------------------------------

    def save_connection(
        self,
        user_id: str,
        data: dict[str, Any],
        *,
        method: str,
        label: str | None,
        status: str = "ok",
    ) -> None:
        blob = self._fernet.encrypt(json.dumps(data).encode())
        now = time.time()
        self._q(
            "INSERT INTO connections(user_id,blob,method,label,status,last_checked,"
            "last_error,updated_at) VALUES(?,?,?,?,?,?,NULL,?) "
            "ON CONFLICT(user_id) DO UPDATE SET blob=excluded.blob, "
            "method=excluded.method, label=excluded.label, status=excluded.status, "
            "last_checked=excluded.last_checked, last_error=NULL, "
            "updated_at=excluded.updated_at",
            (user_id, blob, method, label, status, now, now),
        )

    def get_connection(self, user_id: str) -> dict[str, Any] | None:
        """Decrypted connection secrets (``token``/``email``/...) or None."""
        row = self._one("SELECT blob FROM connections WHERE user_id=?", (user_id,))
        if not row:
            return None
        try:
            return json.loads(self._fernet.decrypt(row["blob"]))
        except InvalidToken:
            return None  # key changed; treat as not connected

    def connection_meta(self, user_id: str) -> sqlite3.Row | None:
        return self._one(
            "SELECT method,label,status,last_checked,last_error,updated_at "
            "FROM connections WHERE user_id=?",
            (user_id,),
        )

    def set_connection_health(
        self, user_id: str, status: str, error: str | None = None
    ) -> None:
        self._q(
            "UPDATE connections SET status=?, last_checked=?, last_error=? "
            "WHERE user_id=?",
            (status, time.time(), error, user_id),
        )

    def delete_connection(self, user_id: str) -> None:
        self._q("DELETE FROM connections WHERE user_id=?", (user_id,))

    # -- oauth: clients ------------------------------------------------------

    def save_client(self, client_id: str, data: str) -> None:
        self._q(
            "INSERT OR REPLACE INTO oauth_clients(client_id,data,created_at) "
            "VALUES(?,?,?)",
            (client_id, data, time.time()),
        )
        # Registration is open (required for Claude's connector); bound the table.
        self._q(
            "DELETE FROM oauth_clients WHERE client_id IN (SELECT client_id FROM "
            "oauth_clients ORDER BY created_at DESC LIMIT -1 OFFSET ?)",
            (MAX_CLIENTS,),
        )

    def get_client(self, client_id: str) -> str | None:
        row = self._one(
            "SELECT data FROM oauth_clients WHERE client_id=?", (client_id,)
        )
        return row["data"] if row else None

    # -- oauth: pending authorization requests -------------------------------

    def save_pending(self, data: dict[str, Any]) -> str:
        pid = new_secret(16)
        self._purge()
        self._q(
            "INSERT INTO pending_auth(id,data,expires) VALUES(?,?,?)",
            (pid, json.dumps(data), time.time() + PENDING_TTL),
        )
        return pid

    def get_pending(self, pid: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT data FROM pending_auth WHERE id=? AND expires>?",
            (pid, time.time()),
        )
        return json.loads(row["data"]) if row else None

    def delete_pending(self, pid: str) -> None:
        self._q("DELETE FROM pending_auth WHERE id=?", (pid,))

    # -- oauth: codes & tokens -----------------------------------------------

    def save_code(self, code: str, data: dict[str, Any]) -> None:
        self._q(
            "INSERT INTO auth_codes(code_hash,data,expires) VALUES(?,?,?)",
            (sha256(code), json.dumps(data), time.time() + CODE_TTL),
        )

    def get_code(self, code: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT data FROM auth_codes WHERE code_hash=? AND expires>?",
            (sha256(code), time.time()),
        )
        return json.loads(row["data"]) if row else None

    def delete_code(self, code: str) -> None:
        self._q("DELETE FROM auth_codes WHERE code_hash=?", (sha256(code),))

    def issue_tokens(
        self,
        user_id: str,
        client_id: str,
        scopes: list[str],
        resource: str | None,
    ) -> tuple[str, str]:
        access, refresh, pair = new_secret(), new_secret(), new_secret(8)
        now = time.time()
        self._purge()
        sc = " ".join(scopes)
        with self._lock:
            for kind, tok, ttl in (
                ("access", access, ACCESS_TTL),
                ("refresh", refresh, REFRESH_TTL),
            ):
                self._q(
                    "INSERT INTO tokens(token_hash,kind,pair_id,user_id,client_id,"
                    "scopes,resource,expires) VALUES(?,?,?,?,?,?,?,?)",
                    (sha256(tok), kind, pair, user_id, client_id, sc, resource,
                     now + ttl),
                )
        return access, refresh

    def get_token(self, token: str, kind: str) -> sqlite3.Row | None:
        return self._one(
            "SELECT * FROM tokens WHERE token_hash=? AND kind=? AND expires>?",
            (sha256(token), kind, time.time()),
        )

    def retire_pair(self, pair_id: str) -> None:
        """Rotate out a pair: drop its access token, but keep the refresh token
        valid for a short grace window so a lost refresh response (network drop,
        client crash before saving) can be retried instead of forcing re-login."""
        with self._lock:
            self._q("DELETE FROM tokens WHERE pair_id=? AND kind='access'", (pair_id,))
            self._q(
                "UPDATE tokens SET expires=MIN(expires, ?) WHERE pair_id=?",
                (time.time() + REFRESH_GRACE, pair_id),
            )

    def revoke_pair(self, pair_id: str) -> None:
        self._q("DELETE FROM tokens WHERE pair_id=?", (pair_id,))

    def revoke_user_tokens(self, user_id: str) -> int:
        with self._lock:
            n = self._db.execute(
                "DELETE FROM tokens WHERE user_id=?", (user_id,)
            ).rowcount
        return n

    def authorized_client_count(self, user_id: str) -> int:
        row = self._one(
            "SELECT COUNT(DISTINCT pair_id) AS n FROM tokens "
            "WHERE user_id=? AND kind='refresh' AND expires>?",
            (user_id, time.time()),
        )
        return row["n"]


_store: Store | None = None


def get_store() -> Store:
    """Process-wide store, created on first use (so stdio never needs a DB)."""
    global _store
    if _store is None:
        from monarch_mcp_server.config import config

        _store = Store(config.data_dir)
    return _store
