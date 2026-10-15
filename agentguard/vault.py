"""Secret-provider boundary. This is an adapter, not a live AgentVault integration."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol


class SecretProvider(Protocol):
    def get(self, name: str) -> str: ...

@dataclass(frozen=True)
class EnvironmentSecretProvider:
    prefix: str = 'AGENTGUARD_SECRET_'

    def get(self, name: str) -> str:
        if not name or not all(c.isascii() and (c.isupper() or c.isdigit() or c == '_') for c in name):
            raise ValueError('Invalid secret name')
        value = os.environ.get(self.prefix + name)
        if not value:
            raise LookupError('Secret unavailable')
        return value

@dataclass(frozen=True)
class VaultTool:
    """Inject a secret into a trusted callable; never expose secret via API output."""
    provider: SecretProvider
    secret_name: str
    operation: object

    def __call__(self, payload):
        return self.operation(payload, self.provider.get(self.secret_name))
