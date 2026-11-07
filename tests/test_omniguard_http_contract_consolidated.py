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
