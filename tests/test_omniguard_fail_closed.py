import asyncio
"""Regression tests for OmniGuard's fail-closed AgentGuard boundary."""
import pytest
from unittest.mock import AsyncMock, Mock
from agentguard import api
from agentguard.omniguard_client import OmniGuardDecision, OmniGuardResult


def test_inspection_failure_blocks(monkeypatch):
    client = Mock()
    client.inspect = AsyncMock(side_effect=ConnectionError("offline"))
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", True)
    monkeypatch.setattr(api, "get_omniguard_client", lambda: client)
    reason = asyncio.run(api._omniguard_inspect("agent", "tool", {"text": "hello"}))
    assert reason is not None


def test_missing_integration_blocks(monkeypatch):
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", False)
    assert asyncio.run(api._omniguard_inspect("agent", "tool", {})) is not None


def test_explicit_allow_passes(monkeypatch):
    client = Mock()
    client.inspect = AsyncMock(return_value=OmniGuardResult(
        decision=OmniGuardDecision.ALLOW,
        confidence=1.0,
        signature="test",
        latency_ms=1.0,
        tier_latencies={},
    ))
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", True)
    monkeypatch.setattr(api, "get_omniguard_client", lambda: client)
    assert asyncio.run(api._omniguard_inspect("agent", "tool", {})) is None


def test_explicit_block_rejects(monkeypatch):
    client = Mock()
    client.inspect = AsyncMock(return_value=OmniGuardResult(
        decision=OmniGuardDecision.BLOCK,
        confidence=1.0,
        signature="test",
        latency_ms=1.0,
        tier_latencies={},
        blocked_reason="policy",
    ))
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", True)
    monkeypatch.setattr(api, "get_omniguard_client", lambda: client)
    assert asyncio.run(api._omniguard_inspect("agent", "tool", {})) == "policy"
