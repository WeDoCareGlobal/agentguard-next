"""Fail-closed regression coverage for the consolidated OmniGuard boundary."""
import asyncio
from types import SimpleNamespace

from fastapi.testclient import TestClient

from agentguard import api
from agentguard.core import Guard, Policy
from agentguard.identity import TokenAuthority


def test_inspection_rejects_unverified_allow(monkeypatch):
    class Client:
        async def inspect(self, messages):
            return SimpleNamespace(decision=api.OmniGuardDecision.ALLOW)
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", True)
    monkeypatch.setattr(api, "get_omniguard_client", lambda: Client())
    assert asyncio.run(api._omniguard_inspect("a", "read", {})) == "Unverified OmniGuard decision"


def test_inspection_rejects_gateway_exception(monkeypatch):
    class Client:
        async def inspect(self, messages):
            raise TimeoutError("gateway unavailable")
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", True)
    monkeypatch.setattr(api, "get_omniguard_client", lambda: Client())
    assert asyncio.run(api._omniguard_inspect("a", "read", {})) == "OmniGuard inspection unavailable"


def test_legacy_route_denies_without_inspector(tmp_path, monkeypatch):
    calls = []
    guard = Guard(str(tmp_path / "audit.db"), b"x" * 32, Policy(allowed=frozenset({"read"})), {"read": lambda p: calls.append(p)})
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", False)
    client = TestClient(api.create_app(guard, "a" * 32, "b" * 32))
    response = client.post("/v1/execute", headers={"x-api-key": "a" * 32}, json={"agent": "bot", "tool": "read", "request_id": "r1", "payload": {}})
    assert response.status_code == 403
    assert not calls


def test_scoped_route_denies_without_inspector(tmp_path, monkeypatch):
    calls = []
    guard = Guard(str(tmp_path / "audit.db"), b"x" * 32, Policy(allowed=frozenset({"read"})), {"read": lambda p: calls.append(p)})
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", False)
    app = api.create_app(guard, "a" * 32, "b" * 32)
    authority = TokenAuthority(b"z" * 32)
    api.attach_scoped_execution(app, guard, authority)
    token = authority.issue("worker", "bot", {"execute"})
    response = TestClient(app).post("/v1/scoped/execute", headers={"authorization": "Bearer " + token}, json={"agent": "bot", "tool": "read", "request_id": "r1", "payload": {}})
    assert response.status_code == 403
    assert not calls


def test_oidc_route_denies_without_inspector(tmp_path, monkeypatch):
    class StubVerifier:
        def verify(self, token, scope):
            if token == "good" and scope == "execute":
                return SimpleNamespace(subject="bot")
            return None

    calls = []
    guard = Guard(str(tmp_path / "audit.db"), b"x" * 32, Policy(allowed=frozenset({"read"})), {"read": lambda p: calls.append(p)})
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", False)
    app = api.create_app(guard, "a" * 32, "b" * 32)
    api.attach_oidc_execution(app, guard, StubVerifier())
    response = TestClient(app).post(
        "/v1/oidc/execute",
        headers={"authorization": "Bearer good"},
        json={"agent": "bot", "tool": "read", "request_id": "r1", "payload": {}},
    )
    assert response.status_code == 403
    assert not calls


def test_legacy_route_denies_unverified_allow(tmp_path, monkeypatch):
    class Client:
        async def inspect(self, messages):
            return SimpleNamespace(decision=api.OmniGuardDecision.ALLOW, signature="not-verified")

    calls = []
    guard = Guard(str(tmp_path / "audit.db"), b"x" * 32, Policy(allowed=frozenset({"read"})), {"read": lambda p: calls.append(p)})
    monkeypatch.setattr(api, "OMNIGUARD_AVAILABLE", True)
    monkeypatch.setattr(api, "get_omniguard_client", lambda: Client())
    client = TestClient(api.create_app(guard, "a" * 32, "b" * 32))
    response = client.post(
        "/v1/execute",
        headers={"x-api-key": "a" * 32},
        json={"agent": "bot", "tool": "read", "request_id": "r1", "payload": {}},
    )
    assert response.status_code == 403
    assert not calls
