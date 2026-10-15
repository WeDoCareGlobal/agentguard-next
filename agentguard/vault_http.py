"""Read-only Vault KV v2 adapter, requiring HTTPS and a supplied token.

Only returns a named secret to trusted in-process code. Never log the token.
"""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import quote
import httpx


@dataclass(frozen=True)
class VaultKV2Provider:
    base_url: str
    token: str
    mount: str = 'secret'
    path: str = 'agentguard'
    timeout: float = 3.0

    def __post_init__(self):
        if (not self.base_url.startswith('https://') or not self.token or
            not 0 < self.timeout <= 30 or
            any(not part or part in ('.', '..') or '/' in part for part in (self.mount, self.path))):
            raise ValueError('Invalid Vault configuration')

    def get(self, name: str) -> str:
        if not name or not name.isascii() or not all(ch.isupper() or ch.isdigit() or ch == '_' for ch in name):
            raise ValueError('Invalid secret name')
        url = f"{self.base_url.rstrip('/')}/v1/{quote(self.mount, safe='')}/data/{quote(self.path, safe='')}"
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False, trust_env=False) as client:
                response = client.get(url, headers={'X-Vault-Token': self.token})
                response.raise_for_status()
                value = response.json()['data']['data'][name]
            if not isinstance(value, str) or not value:
                raise LookupError('Secret unavailable')
            return value
        except (httpx.HTTPError, KeyError, TypeError, ValueError, RuntimeError):
            raise LookupError('Secret unavailable') from None
