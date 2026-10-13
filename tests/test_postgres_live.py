"""Opt-in real PostgreSQL integration. Run with AG_TEST_POSTGRES_DSN."""
import os, uuid, threading
import pytest

@pytest.mark.skipif(not os.environ.get('AG_TEST_POSTGRES_DSN'), reason='AG_TEST_POSTGRES_DSN not set')
def test_live_postgres_parallel_admission_and_audit():
    import psycopg
    from agentguard.coordination import PostgresCoordinator
    from agentguard.shared_control import SharedControl
    from agentguard.central_audit import PostgresAudit
    dsn=os.environ['AG_TEST_POSTGRES_DSN']
    def connect(): return psycopg.connect(dsn)
    coord=PostgresCoordinator(connect); shared=SharedControl(connect)
    audit=PostgresAudit(connect,b'k'*32)
    shared.initialize();coord.initialize();audit.initialize()
    # Test requires a dedicated, disposable PostgreSQL database.
    shared.set_halt(False)
    agent='test-'+uuid.uuid4().hex
    results=[]; lock=threading.Lock(); barrier=threading.Barrier(4)
    def worker():
        barrier.wait()
        ok, reason=coord.admit(request_id=str(uuid.uuid4()),agent=agent,fingerprint='fp',limit=1,approval_required=False,approval_token=None)
        with lock: results.append((ok,reason))
    ts=[threading.Thread(target=worker) for _ in range(4)]
    for t in ts:t.start()
    for t in ts:t.join(timeout=20)
    assert len(results)==4 and sum(ok for ok,_ in results)==1
    stream='test-'+uuid.uuid4().hex
    audit.append(stream,{'agent':agent,'event':'admitted'})
    assert audit.verify(stream)==(True,1)
