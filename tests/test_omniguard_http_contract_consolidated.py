"""Transport contract regression tests for the OmniGuard gateway."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentguard.omniguard_client import OmniGuardClient


def response(status, decision):
    result = MagicMock()
    result.status_code = status
    result.headers = {"X-Governance-Decision": decision}
    result.json.return_value = {}
    return result


def test_relative_endpoint_preserves_v1_prefix():
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        post.return_value = response(200, "ALLOW")
        client = OmniGuardClient(base_url="https://gateway.example/v1", api_key="test")
        async def run():
            try:
                await client.inspect([{"role": "user", "content": "hello"}])
            finally:
                await client.close()
        asyncio.run(run())
        assert post.call_args.args[0] == "chat/completions"


@pytest.mark.parametrize("status,decision", [(401, "ALLOW"), (500, "ALLOW"), (403, "ALLOW"), (200, "INVALID")])
def test_untrusted_transport_cannot_authorize(status, decision):
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        post.return_value = response(status, decision)
        client = OmniGuardClient(base_url="https://gateway.example/v1", api_key="test")
        async def run():
            try:
                with pytest.raises(ValueError):
                    await client.inspect([{"role": "user", "content": "hello"}])
            finally:
                await client.close()
        asyncio.run(run())


def test_gateway_url_uses_environment_when_not_explicit(monkeypatch):
    monkeypatch.setenv("OMNIGUARD_BASE_URL", "https://gateway.example/v1/")
    client = OmniGuardClient(api_key="test")
    assert client.base_url == "https://gateway.example/v1"


def test_explicit_gateway_url_overrides_environment(monkeypatch):
    monkeypatch.setenv("OMNIGUARD_BASE_URL", "https://unwanted.example/v1")
    client = OmniGuardClient(base_url="https://chosen.example/v1", api_key="test")
    assert client.base_url == "https://chosen.example/v1"


def test_403_block_is_not_authorization():
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as post:
        post.return_value = response(403, "BLOCK")
        client = OmniGuardClient(base_url="https://gateway.example/v1", api_key="test")
        async def run():
            try:
                return await client.inspect([{"role": "user", "content": "hello"}])
            finally:
                await client.close()
        result = asyncio.run(run())
        assert result.decision.value == "BLOCK"
