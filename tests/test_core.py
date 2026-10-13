import os
import pytest
from agentguard.core import Guard, Policy
from agentguard.api import create_app

@pytest.fixture
def setup(tmp_path):
    called = []
    p = Policy(frozenset({'read','write'}), frozenset({'blocked'}), frozenset({'write'}))
    g = Guard(str(tmp_path/'audit.db'), b'k'*32, p, {'read':lambda p: called.append(p) or 'ok','write':lambda p: called.append(p) or 'done'}, max_per_minute=2)
    return g,called

def test_default_deny(setup):
    g,c=setup
    assert g.execute('a','unknown',{},'1')['decision']=='DENY' and not c

def test_allow_and_replay(setup):
    g,c=setup
    assert g.execute('a','read',{'x':1},'1')['result']=='ok'
    assert g.execute('a','read',{'x':1},'1')['reason']=='replay'
    assert len(c)==1

def test_approval_binding(setup):
    g,c=setup
    assert g.execute('a','write',{'x':1},'1')['decision']=='APPROVAL_REQUIRED'
    t=g.grant('a','write',{'x':1})
    assert g.execute('a','write',{'x':2},'2',t)['decision']=='APPROVAL_REQUIRED'
    assert g.execute('a','write',{'x':1},'3',t)['decision']=='ALLOW'
    assert g.execute('a','write',{'x':1},'4',t)['decision']=='APPROVAL_REQUIRED'
    assert len(c)==1

def test_kill_switch(setup):
    g,c=setup
    g.set_kill_switch(True)
    assert g.execute('a','read',{},'1')['reason']=='kill_switch'
    assert not c

def test_rate_limit(setup):
    g,c=setup
    assert g.execute('a','read',{},'1')['decision']=='ALLOW'
    assert g.execute('a','read',{},'2')['decision']=='ALLOW'
    assert g.execute('a','read',{},'3')['reason']=='rate_limit'

def test_audit_tampering(setup):
    g,_=setup
    g.execute('a','read',{},'1')
    assert g.verify_audit()
    g.db.execute("UPDATE events SET body='tampered' WHERE seq=1")
    assert not g.verify_audit()

def test_bad_key(tmp_path):
    with pytest.raises(ValueError): Guard(str(tmp_path/'x.db'),b'short',Policy(),{})

def test_exception_is_hidden(tmp_path):
    def broken(_): raise RuntimeError('secret details')
    g=Guard(str(tmp_path/'x.db'),b'x'*32,Policy(frozenset({'bad'})),{'bad':broken})
    assert g.execute('a','bad',{},'1') == {'decision':'ERROR','reason':'tool_execution_failed'}

def test_api_auth(setup):
    from fastapi.testclient import TestClient
    g,_=setup
    client=TestClient(create_app(g,'a'*32,'b'*32))
    assert client.post('/v1/execute',json={'agent':'a','tool':'read','request_id':'1','payload':{}}).status_code==401
    assert client.post('/v1/execute',headers={'x-api-key':'a'*32},json={'agent':'a','tool':'read','request_id':'1','payload':{}}).json()['decision']=='ALLOW'
    assert client.post('/v1/admin/halt',headers={'x-api-key':'a'*32},json={'enabled':True}).status_code==401
    assert client.post('/v1/admin/halt',headers={'x-admin-key':'b'*32},json={'enabled':True}).status_code==200

def test_policy_deny_precedence():
    p=Policy(frozenset({'x'}),frozenset({'x'}))
    assert p.decide('x')=='DENY'
