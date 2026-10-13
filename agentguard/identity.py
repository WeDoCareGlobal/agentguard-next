"""Scoped HMAC bearer tokens for isolated deployments; not an OIDC provider."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def _decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


@dataclass(frozen=True)
class Principal:
    subject: str
    scopes: frozenset[str]
    agent: str


class TokenAuthority:
    def __init__(self, key: bytes, issuer: str = 'agentguard-local'):
        if len(key) < 32:
            raise ValueError('Signing key too short')
        self._key = key
        self.issuer = issuer

    def issue(self, subject: str, agent: str, scopes: set[str], ttl: int = 300) -> str:
        if not subject or not agent or not scopes or not 1 <= ttl <= 3600:
            raise ValueError('Invalid token request')
        body = {'iss': self.issuer, 'sub': subject, 'agent': agent, 'scopes': sorted(scopes),
                'exp': int(time.time()) + ttl, 'jti': secrets.token_hex(16)}
        payload = _b64(json.dumps(body, sort_keys=True, separators=(',', ':')).encode())
        sig = _b64(hmac.new(self._key, payload.encode(), hashlib.sha256).digest())
        return payload + '.' + sig

    def verify(self, token: str, scope: str, agent: str | None = None) -> Principal | None:
        try:
            payload, signature = token.split('.')
            expected = hmac.new(self._key, payload.encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(_decode(signature), expected):
                return None
            obj = json.loads(_decode(payload))
            if (obj['iss'] != self.issuer or not isinstance(obj['exp'], int)
                    or obj['exp'] <= time.time() or not obj['sub'] or not obj['agent']
                    or not isinstance(obj['scopes'], list) or scope not in obj['scopes']
                    or (agent is not None and obj['agent'] != agent)):
                return None
            return Principal(obj['sub'], frozenset(obj['scopes']), obj['agent'])
        except (ValueError, KeyError, TypeError, UnicodeError, OverflowError):
            return None
