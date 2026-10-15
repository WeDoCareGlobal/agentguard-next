from agentguard.core import Guard, Policy

class Store:
    def __init__(self):
        self.seen = set()
        self.fail = False
    def reserve(self, request_id, agent, fp, limit):
        if self.fail:
            raise ConnectionError('db unavailable')
        if request_id in self.seen:
            return False
        self.seen.add(request_id)
        return True

def build(tmp_path, store, calls):
    return Guard(str(tmp_path / 'audit.db'), b'x'*32,
                 Policy(allowed=frozenset({'read'})),
                 {'read': lambda p: calls.append(p) or 'ok'},
                 reservation_store=store)

def test_distributed_reservation_blocks_cross_worker_replay(tmp_path):
    store, calls = Store(), []
    a = build(tmp_path, store, calls)
    assert a.execute('bot','read',{},'r1')['decision'] == 'ALLOW'
    b = build(tmp_path, store, calls)
    assert b.execute('bot','read',{},'r1')['decision'] == 'DENY'
    assert len(calls) == 1
    assert b.verify_audit()

def test_coordination_failure_fails_closed(tmp_path):
    store, calls = Store(), []
    store.fail = True
    guard = build(tmp_path, store, calls)
    result = guard.execute('bot','read',{},'r1')
    assert result == {'decision':'DENY','reason':'coordination_unavailable'}
    assert calls == []
    assert guard.verify_audit()

def test_denied_policy_never_reserves(tmp_path):
    store, calls = Store(), []
    guard = build(tmp_path, store, calls)
    assert guard.execute('bot','write',{},'r1')['decision'] == 'DENY'
    assert store.seen == set()
