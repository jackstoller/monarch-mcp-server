"""Tests for the OAuth resource-server JWT verification.

Covers the four validation outcomes that matter for the MCP auth spec:
valid token, expired token, wrong audience, wrong issuer (plus a malformed
token and a missing-exp token for good measure).
"""

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from monarch_mcp_server.config import OAuthConfig
from monarch_mcp_server.oauth import JwtTokenVerifier

ISSUER = "https://idp.example.com/"
AUDIENCE = "https://monarch-mcp.example.com"
OTHER = "https://evil.example.com"


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key


@pytest.fixture
def verifier(keypair):
    cfg = OAuthConfig(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_uri="https://idp.example.com/jwks.json",
        read_scope="monarch:read",
        write_scope="monarch:write",
        public_url=AUDIENCE,
    )
    v = JwtTokenVerifier(cfg)

    # Replace the network-backed JWKS client with one returning our public key.
    class _FakeSigningKey:
        key = keypair.public_key()

    class _FakeJwksClient:
        def get_signing_key_from_jwt(self, token):
            return _FakeSigningKey()

    v._jwks_client = _FakeJwksClient()
    return v


def _make_token(keypair, *, aud=AUDIENCE, iss=ISSUER, exp_offset=3600, scope="monarch:read", include_exp=True):
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": "user-123",
        "azp": "client-abc",
        "scope": scope,
        "iat": int(time.time()),
        "nbf": int(time.time()) - 10,
    }
    if include_exp:
        claims["exp"] = int(time.time()) + exp_offset
    return jwt.encode(claims, keypair, algorithm="RS256")


@pytest.mark.asyncio
async def test_valid_token_accepted(verifier, keypair):
    token = _make_token(keypair, scope="monarch:read monarch:write")
    access = await verifier.verify_token(token)
    assert access is not None
    assert access.subject == "user-123"
    assert access.client_id == "client-abc"
    assert set(access.scopes) == {"monarch:read", "monarch:write"}


@pytest.mark.asyncio
async def test_expired_token_rejected(verifier, keypair):
    token = _make_token(keypair, exp_offset=-60)
    assert await verifier.verify_token(token) is None


@pytest.mark.asyncio
async def test_wrong_audience_rejected(verifier, keypair):
    token = _make_token(keypair, aud=OTHER)
    assert await verifier.verify_token(token) is None


@pytest.mark.asyncio
async def test_wrong_issuer_rejected(verifier, keypair):
    token = _make_token(keypair, iss=OTHER)
    assert await verifier.verify_token(token) is None


@pytest.mark.asyncio
async def test_missing_exp_rejected(verifier, keypair):
    token = _make_token(keypair, include_exp=False)
    assert await verifier.verify_token(token) is None


@pytest.mark.asyncio
async def test_malformed_token_rejected(verifier):
    assert await verifier.verify_token("not-a-jwt") is None


@pytest.mark.asyncio
async def test_token_signed_by_other_key_rejected(verifier):
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "x", "exp": int(time.time()) + 60},
        attacker,
        algorithm="RS256",
    )
    assert await verifier.verify_token(forged) is None
