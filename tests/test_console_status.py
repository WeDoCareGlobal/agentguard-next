import os
from fastapi.testclient import TestClient
from agentguard.core import Guard, Policy
from agentguard.api import create_app, attach_optional_console

KEY = b"z" * 32

def test_console_auth_escaping_and_headers(tmp_path):
    g = Guard(str(tmp_path/'a.db'), KEY, Policy(allowed=frozenset({'echo'})), {'echo':lambda x:x})
    g._audit({'event':'<script>alert(1)</script>'})
    app=create_app(g, 'a'*32, 'b'*32)
    attach_optional_console(app,g,'b'*32)
    c=TestClient(app)
    assert c.get('/v1/admin/console').status_code==401
    r=c.get('/v1/admin/console',headers={'x-admin-key':'b'*32})
    assert r.status_code==200 and '&lt;script&gt;' in r.text and '<script>' not in r.text
    assert 'frame-ancestors' in r.headers['content-security-policy']
    assert r.headers['cache-control']=='no-store'

def test_console_status_reports_central_outage(tmp_path):
    class Offline:
        def verify(self,stream): raise OSError('offline')
    g=Guard(str(tmp_path/'b.db'),KEY,Policy(),{},central_audit=Offline())
    app=create_app(g,'a'*32,'b'*32);attach_optional_console(app,g,'b'*32)
    c=TestClient(app)
    r=c.get('/v1/admin/status',headers={'x-admin-key':'b'*32})
    assert r.status_code==200 and r.json()['healthy'] is False
    assert r.json()['central']['error'].startswith('unavailable')
