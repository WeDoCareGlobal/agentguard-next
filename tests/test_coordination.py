from agentguard.core import Guard, Policy

class FakeCoordinator:
    def __init__(self):
        self.seen = set()
        self.tokens = {'ok'}
        self.halted = False
        self.unavailable = False
        self.calls = 0
    def admit(self, *, request_id, agent, fingerprint, limit, approval_required, approval_token):
        if self.unavailable: raise ConnectionError('database unavailable')
        if self.halted: return False, 'kill_switch'
        if request_id in self.seen: return False, 'replay'
        if self.calls >= limit: return False, 'rate_limit'
        if approval_required and approval_token not in self.tokens: return False, 'approval_missing_or_invalid'
        if approval_required: self.tokens.remove(approval_token)
        self.seen.add(request_id)
        self.calls += 1
        return True, 'admitted'

def make(tmp_path, c, calls, n='one', limit=3):
    return Guard(str(tmp_path / f'{n}.db'), b'k'*32,
        Policy(allowed=frozenset({'write'}), approval_required=frozenset({'write'})),
        {'write': lambda p: calls.append(p)}, max_per_minute=limit, coordinator=c)

def test_approval_not_consumed_on_rate_limit(tmp_path):
    c=FakeCoordinator(); calls=[]; g=make(tmp_path,c,calls,limit=1)
    assert g.execute('a','write',{},'one','ok')['decision']=='ALLOW'
    c.tokens.add('second')
    assert g.execute('a','write',{},'two','second')['reason']=='rate_limit'
    assert 'second' in c.tokens
    assert len(calls)==1

def test_replay_across_instances(tmp_path):
    c=FakeCoordinator(); c.tokens={'first','second'}; calls=[]
    a=make(tmp_path,c,calls,'a'); b=make(tmp_path,c,calls,'b')
    assert a.execute('a','write',{},'same','first')['decision']=='ALLOW'
    assert b.execute('a','write',{},'same','second')['reason']=='replay'
    assert 'second' in c.tokens and len(calls)==1

def test_coordinator_failure_closed(tmp_path):
    c=FakeCoordinator(); c.unavailable=True; calls=[]
    g=make(tmp_path,c,calls)
    assert g.execute('a','write',{},'id','ok')['reason']=='coordination_unavailable'
    assert calls==[]

def test_coordinator_kill_switch(tmp_path):
    c=FakeCoordinator(); c.halted=True; calls=[]
    g=make(tmp_path,c,calls)
    assert g.execute('a','write',{},'id','ok')['reason']=='kill_switch'
    assert calls==[]
