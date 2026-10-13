import pytest
from agentguard.central_audit import PostgresAudit, canonical_event, event_mac

class Result:
    def __init__(self, rows): self.rows = rows
    def fetchone(self): return self.rows[0] if self.rows else None
    def fetchall(self): return self.rows

class FakeConnection:
    def __init__(self, data): self.data = data
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def transaction(self): return self
    def execute(self, sql, args=()):
        if 'pg_advisory_xact_lock' in sql or sql.strip().startswith('CREATE'): return Result([])
        if sql.startswith('INSERT INTO ag_audit_events'):
            self.data.append(args); return Result([])
        if 'ORDER BY sequence DESC' in sql:
            rows = [(r[1],r[5]) for r in self.data if r[0]==args[0]]
            return Result([rows[-1]] if rows else [])
        if 'SELECT sequence,recorded_at' in sql:
            return Result([(r[1],r[2],r[3],r[4],r[5]) for r in self.data if r[0]==args[0]])
        raise AssertionError(sql)

def test_canonical_order():
    assert canonical_event({'z':1,'a':2}) == canonical_event({'a':2,'z':1})

def test_requires_strong_key():
    with pytest.raises(ValueError): PostgresAudit(lambda:None, b'short')

def test_append_and_verify_detects_mutation():
    data=[]; audit=PostgresAudit(lambda:FakeConnection(data), b'k'*32)
    a=audit.append('org1', {'decision':'deny'})
    b=audit.append('org1', {'decision':'allow'})
    assert (a.sequence,b.sequence)==(1,2)
    assert audit.verify('org1') == (True,2)
    data[0]=(*data[0][:3],'{"decision":"allow"}',*data[0][4:])
    assert audit.verify('org1') == (False,0)

def test_sequence_gap_detected():
    data=[]; audit=PostgresAudit(lambda:FakeConnection(data), b'k'*32)
    audit.append('s', {'x':1}); audit.append('s', {'x':2})
    data.pop(0)
    assert audit.verify('s') == (False,0)

def test_mac_binds_stream():
    args=(1, 12.0, '{}', '0'*64)
    assert event_mac(b'k'*32,'a',*args)!=event_mac(b'k'*32,'b',*args)
