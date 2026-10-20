"""HTTP contract tests for AgentGuard -> OmniGuard; no live gateway required."""
import asyncio

import httpx
import pytest

from agentguard.omniguard_client import OmniGuardClient, OmniGuardDecision


def _run_with_response(status, headers=None, body=None):
    seen = []

    def handler(request):
        seen.append((request.url.path, request.headers.get("x-api-key")))
        return httpx.Response(status, headers=headers or {}, json=body or {})

    async def run():
        gateway = OmniGuardClient(base_url="https://gateway.example/v1", api_key="test-only-key")
        gateway._client = httpx.AsyncClient(
            base_url=gateway.base_url,
            transport=httpx.MockTransport(handler),
            headers={"X-API-Key": gateway.api_key},
        )
        try:
            return await gateway.inspect([{"role": "user", "content": "test"}])
        finally:
            await gateway.close()

    return asyncio.run(run()), seen


def test_explicit_allow_requires_header():
    result, seen = _run_with_response(200, {"X-Governance-Decision": "ALLOW"})
    assert result.decision == OmniGuardDecision.ALLOW
    assert seen == [("/v1/chat/completions", "test-only-key")]


def test_explicit_block_is_denied():
    result, _ = _run_with_response(403, body={"detail": "policy denied"})
    assert result.decision == OmniGuardDecision.BLOCK


@pytest.mark.parametrize("status,headers", [
    (200, {}),
    (200, {"X-Governance-Decision": "BLOCK"}),
    (500, {}),
    (401, {}),
])
def test_missing_allow_or_gateway_errors_never_pass(status, headers):
    with pytest.raises((ValueError, httpx.HTTPStatusError)):
        _run_with_response(status, headers)
