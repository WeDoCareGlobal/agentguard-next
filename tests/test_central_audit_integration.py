from agentguard.core import Guard, Policy

class RecordingAudit:
    def __init__(self, fail=False):
        self.events=[]
        self.fail=fail
    def append(self, stream, event):
        if self.fail: raise ConnectionError('unavailable')
        self.events.append((stream,event))

def test_allowed_call_emits_central_decision_and_completion(tmp_path):
    audit=RecordingAudit()
    g=Guard(str(tmp_path/'a.db'), b'k'*32, Policy(allowed=frozenset({'safe'})), {'safe':lambda x:x}, central_audit=audit)
    assert g.execute('bot','safe',{'a':1},'id1')['decision']=='ALLOW'
    assert [e[1]['event'] for e in audit.events]==['decision','execution_completed']

def test_central_audit_failure_blocks_tool(tmp_path):
    calls=[]
    g=Guard(str(tmp_path/'b.db'), b'k'*32, Policy(allowed=frozenset({'safe'})), {'safe':lambda x:calls.append(x)}, central_audit=RecordingAudit(fail=True))
    assert g.execute('bot','safe',{},'id2')['reason']=='central_audit_unavailable'
    assert not calls

def test_denied_call_centrally_logged(tmp_path):
    audit=RecordingAudit()
    g=Guard(str(tmp_path/'c.db'), b'k'*32, Policy(), {}, central_audit=audit)
    assert g.execute('bot','missing',{},'id3')['decision']=='DENY'
    assert audit.events[0][1]['decision']=='DENY'
