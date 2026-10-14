import pytest
from agentguard.core import Guard, Policy


def test_corrupt_audit_blocks_execution_before_tool_or_reservation(tmp_path):
    calls = []
    guard = Guard(str(tmp_path / 'audit.db'), b'k' * 32,
                  Policy(frozenset({'read'})), {'read': lambda p: calls.append(p)})
    guard.execute('agent', 'read', {}, 'first')
    guard.db.execute("UPDATE events SET body='tampered' WHERE seq=1")
    result = guard.execute('agent', 'read', {}, 'second')
    assert result == {'decision': 'DENY', 'reason': 'audit_integrity_failure'}
    assert len(calls) == 1
    assert guard.db.execute("SELECT count(*) FROM requests WHERE request_id='second'").fetchone()[0] == 0


def test_corrupt_audit_blocks_approval_issuance(tmp_path):
    guard = Guard(str(tmp_path / 'audit.db'), b'k' * 32,
                  Policy(frozenset({'write'}), approval_required=frozenset({'write'})),
                  {'write': lambda p: p})
    guard.grant('agent', 'write', {})
    guard.db.execute("UPDATE events SET signature='tampered' WHERE seq=1")
    with pytest.raises(RuntimeError, match='audit_integrity_failure'):
        guard.grant('agent', 'write', {})
    assert guard.db.execute('SELECT count(*) FROM approvals').fetchone()[0] == 1
