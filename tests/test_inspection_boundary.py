from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from agentguard.api import attach_oidc_execution, attach_scoped_execution, create_app
from agentguard.core import Guard, Policy
from agentguard.identity import TokenAuthority
from agentguard.omniguard_client import OmniGuardClient, OmniGuardDecision


@pytest.mark.parametrize('route', ['key', 'scoped', 'oidc'])
@pytest.mark.parametrize('outcome', ['timeout', 'allow', 'block'])
def test_every_route_blocks_unverified_inspection(tmp_path, route, outcome):
    calls = []
    guard = Guard(str(tmp_path/'audit.db'), b'x'*32, Policy(allowed=frozenset({'read'})), {'read': lambda p: calls.append(p)})
    app = create_app(guard, 'a'*32, 'b'*32)
    authority = TokenAuthority(b'c'*32)
    attach_scoped_execution(app, guard, authority)
    verifier = SimpleNamespace(verify=lambda *args: SimpleNamespace(subject='a'))
    attach_oidc_execution(app, guard, verifier)
    paths = {'key': '/v1/execute', 'scoped': '/v1/scoped/execute', 'oidc': '/v1/oidc/execute'}
    headers = {'key': {'x-api-key': 'a'*32}, 'scoped': {'authorization': 'Bearer '+authority.issue('a','a',{'execute'})}, 'oidc': {'authorization':'Bearer verified'}}
    inspect = AsyncMock()
    if outcome == 'timeout':
        inspect.side_effect = TimeoutError()
    else:
        inspect.return_value = SimpleNamespace(decision=OmniGuardDecision.ALLOW if outcome == 'allow' else OmniGuardDecision.BLOCK, blocked_reason='blocked')
    with patch('agentguard.api.get_omniguard_client', return_value=SimpleNamespace(inspect=inspect)):
        response = TestClient(app).post(paths[route], headers=headers[route], json={'agent':'a','tool':'read','payload':{},'request_id':'one'})
    assert response.status_code == 403
    assert calls == []
    assert guard.db.execute('SELECT COUNT(*) FROM requests').fetchone()[0] == 0
    guard.db.close()

def test_missing_key_does_not_contact_gateway(monkeypatch):
    monkeypatch.delenv('OMNIGUARD_API_KEY', raising=False)
    client = OmniGuardClient()
    with pytest.raises(RuntimeError, match='must be configured'):
        import asyncio
        asyncio.run(client.inspect([]))
    assert client._client is None
