"""Regression tests: optional OmniGuard must never silently fail open."""
import asyncio
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from agentguard import api


def test_omniguard_unavailable_denies(monkeypatch):
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", False)
    with pytest.raises(HTTPException) as error:
        asyncio.run(api._omniguard_inspect("agent", "tool", {}))
    assert error.value.status_code == 503


def test_omniguard_error_denies(monkeypatch):
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", True)
    monkeypatch.setattr(api, "get_omniguard_client", lambda: type("Client", (), {"inspect": AsyncMock(side_effect=RuntimeError("offline"))})())
    with pytest.raises(HTTPException) as error:
        asyncio.run(api._omniguard_inspect("agent", "tool", {}))
    assert error.value.status_code == 503


def test_omniguard_unknown_decision_denies(monkeypatch):
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", True)
    monkeypatch.setattr(api, "OmniGuardDecision", type("Decision", (), {"ALLOW": "allow", "BLOCK": "block"}))
    monkeypatch.setattr(api, "get_omniguard_client", lambda: type("Client", (), {"inspect": AsyncMock(return_value=type("Result", (), {"decision": "unknown"})())})())
    with pytest.raises(HTTPException) as error:
        asyncio.run(api._omniguard_inspect("agent", "tool", {}))
    assert error.value.status_code == 403
