import os
from fastapi.testclient import TestClient
from agentguard.api import create_app, attach_oidc_execution
from agentguard.core import Guard, Policy
from agentguard.postgres import PostgresReservationStore

class StubVerifier:
    def verify(self, token, scope):
        if token == 'good' and scope == 'execute':
            return type('Principal', (), {'subject': 'bot'})()
        return None

def test_oidc_boundary(tmp_path):
    calls = []
    guard = Guard(str(tmp_path / 'db.sqlite'), b'x'*32, Policy(allowed=frozenset({'read'})), {'read': lambda p: calls.append(p) or 'ok'})
    app = create_app(guard, 'a'*32, 'b'*32)
    attach_oidc_execution(app, guard, StubVerifier())
    client = TestClient(app)
    data = {'agent': 'bot', 'tool': 'read', 'request_id': 'r1', 'payload': {}}
    assert client.post('/v1/oidc/execute', json=data).status_code == 401
    assert client.post('/v1/oidc/execute', json=data, headers={'Authorization':'Bearer bad'}).status_code == 401
    assert client.post('/v1/oidc/execute', json={**data, 'agent':'other'}, headers={'Authorization':'Bearer good'}).status_code == 403
    response = client.post('/v1/oidc/execute', json=data, headers={'Authorization':'Bearer good'})
    assert response.status_code == 200 and response.json()['decision'] == 'ALLOW'
    assert len(calls) == 1

class FakeCursor:
    def __init__(self, result=None): self.result = result
    def fetchone(self): return self.result

class FakeConnection:
    def __init__(self): self.rows = {}; self.locked = False
    def transaction(self):
        class Tx:
            def __enter__(_): self.locked=True
            def __exit__(_, *args): self.locked=False
        return Tx()
    def execute(self, query, args=()):
        if 'SELECT 1 FROM guard_reservations' in query:
            return FakeCursor((1,) if args[0] in self.rows else None)
        if 'SELECT count(*)' in query:
            return FakeCursor((sum(1 for row in self.rows.values() if row[0]==args[0] and row[1]>args[1]),))
        if 'INSERT INTO guard_reservations' in query:
            self.rows[args[0]] = (args[1], args[3])
        return FakeCursor()

def test_reservation_replay_and_limit():
    store=PostgresReservationStore(FakeConnection())
    assert store.reserve('1','bot','hash',1,100)
    assert not store.reserve('1','bot','hash',1,100)
    assert not store.reserve('2','bot','hash',1,101)
    assert store.reserve('2','bot','hash',1,161)
    assert not store.reserve('3','bot','hash',0,162)
