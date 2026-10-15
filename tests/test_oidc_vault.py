import base64
import json
import time
from unittest.mock import patch
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from agentguard.oidc import OIDCVerifier
from agentguard.vault_http import VaultKV2Provider


def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')


def setup_oidc():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()
    jwks = {'keys': [{'kid': 'one', 'kty': 'RSA', 'alg': 'RS256', 'n': b64(public.n.to_bytes(256, 'big')), 'e': b64(public.e.to_bytes(3, 'big'))}]}
    return private, OIDCVerifier('https://issuer.example', 'agentguard', jwks)


def sign(private, **overrides):
    claims = {'iss': 'https://issuer.example', 'aud': 'agentguard', 'sub': 'user1', 'scope': 'execute read', 'iat': time.time(), 'exp': time.time() + 120}
    claims.update(overrides)
    header = b64(json.dumps({'alg': 'RS256', 'kid': 'one', 'typ': 'JWT'}).encode())
    body = b64(json.dumps(claims).encode())
    signing = (header + '.' + body).encode()
    return signing.decode() + '.' + b64(private.sign(signing, padding.PKCS1v15(), hashes.SHA256()))


def test_oidc_valid():
    key, verifier = setup_oidc()
    assert verifier.verify(sign(key), 'execute').subject == 'user1'


def test_oidc_denies_wrong_audience():
    key, verifier = setup_oidc()
    assert verifier.verify(sign(key, aud='other'), 'execute') is None


def test_oidc_denies_expired():
    key, verifier = setup_oidc()
    assert verifier.verify(sign(key, exp=time.time() - 120), 'execute') is None


def test_oidc_denies_missing_scope():
    key, verifier = setup_oidc()
    assert verifier.verify(sign(key), 'admin') is None


def test_oidc_denies_tampering():
    key, verifier = setup_oidc()
    token = sign(key)
    assert verifier.verify(token[:-3] + 'aaa', 'execute') is None


def test_vault_requires_https():
    with pytest.raises(ValueError):
        VaultKV2Provider('http://vault', 'token')


def test_vault_rejects_bad_names():
    vault = VaultKV2Provider('https://vault.example', 'token')
    with pytest.raises(ValueError):
        vault.get('../TOKEN')


def test_vault_failure_closed():
    vault = VaultKV2Provider('https://vault.example', 'token')
    with patch('httpx.Client', side_effect=RuntimeError('test')):
        with pytest.raises(LookupError):
            vault.get('API_KEY')
