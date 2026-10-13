from agentguard.core import Guard, Policy


def test_local_rate_limit_does_not_burn_approval(tmp_path):
    calls = []
    policy = Policy(frozenset({'read', 'write'}), approval_required=frozenset({'write'}))
    guard = Guard(str(tmp_path / 'db.sqlite'), b'z' * 32, policy,
                  {'read': lambda _: calls.append('read'), 'write': lambda _: calls.append('write')},
                  max_per_minute=1)
    token = guard.grant('agent', 'write', {'task': 1})
    assert guard.execute('agent', 'read', {}, 'one')['decision'] == 'ALLOW'
    denied = guard.execute('agent', 'write', {'task': 1}, 'two', token)
    assert denied == {'decision': 'DENY', 'reason': 'rate_limit'}
    token_hash = __import__('hashlib').sha256(token.encode()).hexdigest()
    assert guard.db.execute('SELECT used FROM approvals WHERE token_hash=?', (token_hash,)).fetchone()[0] == 0
    assert calls == ['read']
