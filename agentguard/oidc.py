"""Offline RS256 OIDC access-token verifier with pinned, operator-supplied JWKS.

JWKS retrieval, rotation and revocation are deployment responsibilities. Fail closed.
"""
from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _decode(value: str) -> bytes:
    if not value or len(value) > 16384:
        raise ValueError('Invalid encoded field')
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


@dataclass(frozen=True)
class OIDCPrincipal:
    subject: str
    issuer: str
    audience: str
    scopes: frozenset[str]


class OIDCVerifier:
    def __init__(self, issuer: str, audience: str, jwks: dict[str, Any], leeway: int = 30):
        if not issuer.startswith('https://') or not audience or not 0 <= leeway <= 120:
            raise ValueError('Invalid OIDC configuration')
        keys = jwks.get('keys', [])
        if not isinstance(keys, list) or len(keys) > 100:
            raise ValueError('Invalid JWKS')
        self.issuer, self.audience, self.leeway = issuer, audience, leeway
        self.keys = {}
        for key in keys:
            if not isinstance(key, dict) or key.get('kty') != 'RSA' or key.get('alg', 'RS256') != 'RS256' or key.get('use', 'sig') != 'sig':
                continue
            kid = key.get('kid')
            if not isinstance(kid, str) or not kid or kid in self.keys:
                raise ValueError('Invalid or duplicate key ID')
            n, e = int.from_bytes(_decode(key['n']), 'big'), int.from_bytes(_decode(key['e']), 'big')
            if n.bit_length() < 2048 or e < 3 or e % 2 == 0:
                raise ValueError('Weak RSA key')
            self.keys[kid] = rsa.RSAPublicNumbers(e, n).public_key()
        if not self.keys:
            raise ValueError('No supported signing keys')

    def verify(self, token: str, required_scope: str) -> OIDCPrincipal | None:
        try:
            if len(token) > 16384 or not required_scope:
                return None
            a, b, c = token.split('.')
            header = json.loads(_decode(a))
            if not isinstance(header, dict) or header.get('alg') != 'RS256' or header.get('typ', 'JWT') not in ('JWT', 'at+jwt'):
                return None
            key = self.keys.get(header.get('kid'))
            if key is None:
                return None
            key.verify(_decode(c), (a + '.' + b).encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
            claims = json.loads(_decode(b))
            now = time.time()
            aud = claims.get('aud')
            if (claims.get('iss') != self.issuer or
                not (aud == self.audience or isinstance(aud, list) and self.audience in aud) or
                not isinstance(claims.get('exp'), (int, float)) or isinstance(claims.get('exp'), bool) or
                claims['exp'] <= now - self.leeway or
                not isinstance(claims.get('iat'), (int, float)) or claims['iat'] > now + self.leeway or
                ('nbf' in claims and (not isinstance(claims['nbf'], (int, float)) or claims['nbf'] > now + self.leeway)) or
                not isinstance(claims.get('sub'), str) or not claims['sub']):
                return None
            scope = claims.get('scope', '')
            if not isinstance(scope, str) or required_scope not in scope.split():
                return None
            return OIDCPrincipal(claims['sub'], self.issuer, self.audience, frozenset(scope.split()))
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError, InvalidSignature):
            return None
