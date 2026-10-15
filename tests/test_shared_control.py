from agentguard.core import Guard, Policy

class FakeShared:
    def __init__(self): self.halt = False; self.approvals = {}; self.fail = False
    def set_halt(self, enabled): self.halt = enabled
    def is_halted(self):
        if self.fail: raise ConnectionError('unavailable')
        return self.halt
    def grant(self, agent, fp, ttl):
        token = f'token-{len(self.approvals)}'
        self.approvals[token] = (agent, fp)
        return token
    def consume(self, agent, fp, token):
        if self.fail: raise ConnectionError('unavailable')
        return self.approvals.pop(token, None) == (agent, fp)

def test_shared_halt_across_guards(tmp_path):
    shared = FakeShared(); calls = []
    def make(n): return Guard(str(tmp_path/f'{n}.db'), b'k'*32, Policy(allowed=frozenset({'read'})), {'read':lambda p:calls.append(p)},shared_control=shared)
    a,b = make('a'),make('b')
    a.set_kill_switch(True)
    assert b.execute('agent','read',{},'id1')['reason']=='kill_switch'
    assert not calls

def test_shared_approval_single_use(tmp_path):
    shared=FakeShared(); calls=[]
    def make(n): return Guard(str(tmp_path/f'{n}.db'),b'k'*32,Policy(allowed=frozenset({'write'}),approval_required=frozenset({'write'})),{'write':lambda p:calls.append(p)},shared_control=shared)
    a,b=make('a'),make('b')
    token=a.grant('agent','write',{'x':1})
    assert b.execute('agent','write',{'x':1},'id1',token)['decision']=='ALLOW'
    assert a.execute('agent','write',{'x':1},'id2',token)['decision']=='APPROVAL_REQUIRED'
    assert len(calls)==1

def test_control_outage_fails_closed(tmp_path):
    shared=FakeShared();shared.fail=True
    guard=Guard(str(tmp_path/'a.db'),b'k'*32,Policy(allowed=frozenset({'read'})),{'read':lambda p:'executed'},shared_control=shared)
    assert guard.execute('agent','read',{},'id1')['decision']=='DENY'
