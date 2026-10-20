import pytest
from fastapi.testclient import TestClient
from agentguard.identity import TokenAuthority
from agentguard.vault import EnvironmentSecretProvider, VaultTool
from agentguard.core import Guard, Policy
from agentguard.api import create_app, attach_optional_console


def test_scoped_identity():
    a = TokenAuthority(b'x'*32)
    t = a.issue('worker', 'agent-1', {'execute'})
    assert a.verify(t, 'execute', 'agent-1').subject == 'worker'
    assert a.verify(t, 'admin') is None
    assert a.verify(t, 'execute', 'other') is None
    assert a.verify(t[:-2]+'zz', 'execute') is None


def test_token_validation():
    with pytest.raises(ValueError): TokenAuthority(b'bad')
    a = TokenAuthority(b'x'*32)
    with pytest.raises(ValueError): a.issue('', 'a', {'execute'})
    with pytest.raises(ValueError): a.issue('s', 'a', {'execute'}, ttl=3601)
    assert a.verify('malformed', 'execute') is None


def test_secret_adapter(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_SECRET_SERVICE', 'private-key')
    p = EnvironmentSecretProvider()
    assert p.get('SERVICE') == 'private-key'
    assert VaultTool(p, 'SERVICE', lambda payload, secret: payload['x'] + len(secret))({'x': 1}) == 12
    with pytest.raises(ValueError): p.get('../bad')
    with pytest.raises(LookupError): p.get('MISSING')


def test_console_auth_and_escape(tmp_path):
    g = Guard(str(tmp_path/'test.db'), b'k'*32, Policy(frozenset({'read'})), {'read':lambda x: 'ok'})
    g.execute('a','read',{'input':'<script>alert(1)</script>'},'req-1')
    app = create_app(g, 'a'*32, 'b'*32)
    attach_optional_console(app,g,'b'*32)
    c = TestClient(app)
    assert c.get('/v1/admin/console').status_code == 401
    r = c.get('/v1/admin/console', headers={'x-admin-key':'b'*32})
    assert r.status_code == 200
    assert 'Audit integrity' in r.text
    assert 'no-store' in r.headers['cache-control']


def test_scoped_endpoint(tmp_path):
    from agentguard.api import attach_scoped_execution
    g = Guard(str(tmp_path/'scoped.db'), b'k'*32, Policy(frozenset({'read'})), {'read': lambda x: 'ok'})
    app = create_app(g, 'a'*32, 'b'*32)
    authority = TokenAuthority(b'x'*32)
    attach_scoped_execution(app, g, authority, enable_omniguard=False)
    c = TestClient(app)
    payload = {'agent':'a', 'tool':'read', 'request_id':'r1', 'payload':{}}
    assert c.post('/v1/scoped/execute', json=payload).status_code == 401
    token = authority.issue('worker','a',{'execute'})
    assert c.post('/v1/scoped/execute',json=payload,headers={'authorization':'Bearer '+token}).json()['decision']=='ALLOW'
    assert c.post('/v1/scoped/execute',json={**payload,'agent':'b'},headers={'authorization':'Bearer '+token}).status_code == 403
