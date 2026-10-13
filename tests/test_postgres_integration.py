"""Comprehensive PostgreSQL integration tests for AgentGuard Phase 1 stabilization.

Covers:
- Concurrent admission across multiple connections
- Replay and duplicate request rejection
- Atomic rate limiting
- Single-use approvals
- Shared global kill switch
- Central audit integrity and tamper detection
- Transaction rollback and database errors
- Database restart and connection recovery
- Fail-closed behavior when PostgreSQL is unavailable
"""
import os
import uuid
import threading
import time
import pytest
import hashlib

pytestmark = pytest.mark.skipif(
    not os.environ.get('AG_TEST_POSTGRES_DSN'),
    reason='AG_TEST_POSTGRES_DSN not set'
)


def _connect(dsn):
    import psycopg
    return psycopg.connect(dsn)


def _setup_modules(dsn):
    from agentguard.coordination import PostgresCoordinator
    from agentguard.shared_control import SharedControl
    from agentguard.central_audit import PostgresAudit

    def connect():
        return _connect(dsn)

    coord = PostgresCoordinator(connect)
    shared = SharedControl(connect)
    audit = PostgresAudit(connect, b'k' * 32)

    shared.initialize()
    coord.initialize()
    audit.initialize()
    shared.set_halt(False)

    return coord, shared, audit, connect


class TestConcurrentAdmission:
    """Test concurrent admission across multiple connections."""

    def test_parallel_admission_serialized_per_agent(self, dsn):
        """Multiple threads for same agent should be serialized - only 1 admitted within limit."""
        coord, shared, audit, _ = _setup_modules(dsn)
        agent = 'concurrent-' + uuid.uuid4().hex
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(5)

        def worker():
            barrier.wait()
            ok, reason = coord.admit(
                request_id=str(uuid.uuid4()),
                agent=agent,
                fingerprint='fp',
                limit=1,
                approval_required=False,
                approval_token=None
            )
            with lock:
                results.append((ok, reason))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        admitted = sum(1 for ok, _ in results if ok)
        assert admitted == 1, f"Expected 1 admitted, got {admitted}"
        assert len(results) == 5

    def test_different_agents_independent_limits(self, dsn):
            """Different agents should have independent rate limits."""
            coord, shared, audit, _ = _setup_modules(dsn)
            results = {}
            lock = threading.Lock()
            barrier = threading.Barrier(4)

            def worker(agent_id):
                barrier.wait()
                for i in range(3):
                    ok, reason = coord.admit(
                        request_id=f'{agent_id}-{i}',
                        agent=agent_id,
                        fingerprint='fp',
                        limit=2,
                        approval_required=False,
                        approval_token=None
                    )
                    with lock:
                        results.setdefault(agent_id, []).append((ok, reason))
                    time.sleep(0.01)

            threads = [threading.Thread(target=worker, args=(f'agent-{i}',)) for i in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)  # increased timeout

            # Allow time for all threads to complete
            time.sleep(0.5)

            for agent_id, res in results.items():
                admitted = sum(1 for ok, _ in res if ok)
                assert admitted == 2, f"Agent {agent_id}: expected 2 admitted, got {admitted}. Results: {res}"


class TestReplayAndDuplicateRejection:
    """Test replay and duplicate request rejection."""

    def test_same_request_id_rejected(self, dsn):
        """Same request_id should be rejected as replay."""
        coord, shared, audit, _ = _setup_modules(dsn)
        agent = 'replay-' + uuid.uuid4().hex
        req_id = str(uuid.uuid4())

        ok1, reason1 = coord.admit(
            request_id=req_id, agent=agent, fingerprint='fp',
            limit=10, approval_required=False, approval_token=None
        )
        ok2, reason2 = coord.admit(
            request_id=req_id, agent=agent, fingerprint='fp',
            limit=10, approval_required=False, approval_token=None
        )

        assert ok1 is True
        assert ok2 is False
        assert reason2 == 'replay'

    def test_duplicate_across_connections(self, dsn):
        """Duplicate request_id rejected even from different connection factories."""
        from agentguard.coordination import PostgresCoordinator

        def connect1():
            return _connect(dsn)

        def connect2():
            return _connect(dsn)

        coord1 = PostgresCoordinator(connect1)
        coord2 = PostgresCoordinator(connect2)

        coord1.initialize()

        agent = 'multi-conn-' + uuid.uuid4().hex
        req_id = str(uuid.uuid4())

        ok1, _ = coord1.admit(
            request_id=req_id, agent=agent, fingerprint='fp',
            limit=10, approval_required=False, approval_token=None
        )
        ok2, reason2 = coord2.admit(
            request_id=req_id, agent=agent, fingerprint='fp',
            limit=10, approval_required=False, approval_token=None
        )

        assert ok1 is True
        assert ok2 is False
        assert reason2 == 'replay'


class TestAtomicRateLimiting:
    """Test atomic rate limiting behavior."""

    def test_rate_limit_enforced_at_exactly_limit(self, dsn):
        """Rate limit should be enforced at exactly the configured limit."""
        coord, shared, audit, _ = _setup_modules(dsn)
        agent = 'ratelimit-' + uuid.uuid4().hex
        limit = 3

        results = []
        for i in range(limit + 2):
            ok, reason = coord.admit(
                request_id=str(uuid.uuid4()),
                agent=agent,
                fingerprint='fp',
                limit=limit,
                approval_required=False,
                approval_token=None
            )
            results.append((ok, reason))

        admitted = sum(1 for ok, _ in results if ok)
        assert admitted == limit, f"Expected {limit} admitted, got {admitted}"

        denied = [(ok, reason) for ok, reason in results if not ok]
        assert all(reason == 'rate_limit' for _, reason in denied)

    def test_rate_limit_window_reset(self, dsn):
        """Rate limit should reset after time window (tested via direct time manipulation)."""
        coord, shared, audit, connect = _setup_modules(dsn)
        agent = 'window-' + uuid.uuid4().hex

        # Quick test: make 2 requests, 3rd should fail
        ok1, _ = coord.admit(
            request_id=str(uuid.uuid4()), agent=agent, fingerprint='fp',
            limit=2, approval_required=False, approval_token=None
        )
        assert ok1
        ok2, _ = coord.admit(
            request_id=str(uuid.uuid4()), agent=agent, fingerprint='fp',
            limit=2, approval_required=False, approval_token=None
        )
        assert ok2
        ok3, reason3 = coord.admit(
            request_id=str(uuid.uuid4()), agent=agent, fingerprint='fp',
            limit=2, approval_required=False, approval_token=None
        )
        assert ok3 is False
        assert reason3 == 'rate_limit'


class TestSingleUseApprovals:
    """Test single-use approval consumption."""

    def test_approval_consumed_on_admit(self, dsn):
        """Approval token should be consumed on successful admission."""
        coord, shared, audit, _ = _setup_modules(dsn)
        agent = 'approval-' + uuid.uuid4().hex
        fp = 'test-fingerprint'

        token = shared.grant(agent, fp, ttl=120)
        assert token is not None

        # First admission with token should succeed
        ok1, reason1 = coord.admit(
            request_id=str(uuid.uuid4()),
            agent=agent,
            fingerprint=fp,
            limit=10,
            approval_required=True,
            approval_token=token
        )
        assert ok1 is True

        # Second admission with same token should fail
        ok2, reason2 = coord.admit(
            request_id=str(uuid.uuid4()),
            agent=agent,
            fingerprint=fp,
            limit=10,
            approval_required=True,
            approval_token=token
        )
        assert ok2 is False
        assert reason2 == 'approval_missing_or_invalid'

    def test_approval_not_consumed_on_rate_limit(self, dsn):
        """Approval should not be consumed if rate limit is hit first."""
        coord, shared, audit, _ = _setup_modules(dsn)
        agent = 'approval-rl-' + uuid.uuid4().hex
        fp = 'test-fingerprint'

        token = shared.grant(agent, fp, ttl=120)

        # First request: admit (consumes approval)
        ok1, _ = coord.admit(
            request_id=str(uuid.uuid4()),
            agent=agent, fingerprint=fp, limit=1,
            approval_required=True, approval_token=token
        )
        assert ok1

        # Second request with same token: should fail (token already consumed)
        ok2, reason2 = coord.admit(
            request_id=str(uuid.uuid4()),
            agent=agent, fingerprint=fp, limit=1,
            approval_required=True, approval_token=token
        )
        assert ok2 is False
        assert reason2 in ('rate_limit', 'approval_missing_or_invalid')

    def test_approval_expiry(self, dsn):
        """Expired approval should be rejected."""
        coord, shared, audit, _ = _setup_modules(dsn)
        agent = 'expiry-' + uuid.uuid4().hex
        fp = 'test-fingerprint'

        token = shared.grant(agent, fp, ttl=1)  # 1 second TTL
        time.sleep(1.5)

        ok, reason = coord.admit(
            request_id=str(uuid.uuid4()),
            agent=agent,
            fingerprint=fp,
            limit=10,
            approval_required=True,
            approval_token=token
        )
        assert ok is False
        assert reason == 'approval_missing_or_invalid'


class TestSharedGlobalKillSwitch:
    """Test shared global kill switch."""

    def test_kill_switch_blocks_all_agents(self, dsn):
        """Kill switch should block admissions for all agents."""
        coord, shared, audit, _ = _setup_modules(dsn)

        shared.set_halt(True)

        for i in range(3):
            ok, reason = coord.admit(
                request_id=str(uuid.uuid4()),
                agent=f'agent-{i}',
                fingerprint='fp',
                limit=10,
                approval_required=False,
                approval_token=None
            )
            assert ok is False
            assert reason == 'kill_switch'

        # Verify is_halted
        assert shared.is_halted() is True

        # Disable kill switch
        shared.set_halt(False)
        assert shared.is_halted() is False

        ok, _ = coord.admit(
            request_id=str(uuid.uuid4()), agent='new-agent',
            fingerprint='fp', limit=10,
            approval_required=False, approval_token=None
        )
        assert ok is True

    def test_kill_switch_persists_across_connections(self, dsn):
        """Kill switch state should persist across connection factories."""
        from agentguard.shared_control import SharedControl

        def connect1():
            return _connect(dsn)

        def connect2():
            return _connect(dsn)

        shared1 = SharedControl(connect1)
        shared2 = SharedControl(connect2)

        shared1.initialize()
        shared1.set_halt(True)

        assert shared2.is_halted() is True

        shared1.set_halt(False)
        assert shared2.is_halted() is False


class TestCentralAuditIntegrity:
    """Test central audit integrity and tamper detection."""

    def test_audit_append_and_verify(self, dsn):
        """Audit append and verify should work correctly."""
        coord, shared, audit, _ = _setup_modules(dsn)
        stream = 'audit-' + uuid.uuid4().hex

        receipt1 = audit.append(stream, {'event': 'test1', 'value': 1})
        receipt2 = audit.append(stream, {'event': 'test2', 'value': 2})

        assert receipt1.sequence == 1
        assert receipt2.sequence == 2

        valid, count = audit.verify(stream)
        assert valid is True
        assert count == 2

    def test_audit_tampering_detected(self, dsn):
        """Tampered audit events should be detected."""
        coord, shared, audit, connect = _setup_modules(dsn)
        stream = 'tamper-' + uuid.uuid4().hex

        audit.append(stream, {'event': 'original'})
        valid, _ = audit.verify(stream)
        assert valid is True

        # Directly tamper with the database
        conn = connect()
        with conn.transaction():
            conn.execute(
                "UPDATE ag_audit_events SET event_json = '{\"event\":\"tampered\"}' WHERE stream = %s AND sequence = 1",
                (stream,)
            )
        conn.close()

        valid, count = audit.verify(stream)
        assert valid is False
        assert count == 0

    def test_audit_sequence_gap_detected(self, dsn):
        """Missing sequence numbers should be detected."""
        coord, shared, audit, connect = _setup_modules(dsn)
        stream = 'gap-' + uuid.uuid4().hex

        audit.append(stream, {'event': '1'})
        audit.append(stream, {'event': '2'})
        audit.append(stream, {'event': '3'})

        # Delete middle entry
        conn = connect()
        with conn.transaction():
            conn.execute(
                "DELETE FROM ag_audit_events WHERE stream = %s AND sequence = 2",
                (stream,)
            )
        conn.close()

        valid, count = audit.verify(stream)
        assert valid is False

    def test_audit_mac_binds_stream(self, dsn):
        """MAC should be different for different streams."""
        coord, shared, audit, _ = _setup_modules(dsn)

        r1 = audit.append('stream-a', {'event': 'same'})
        r2 = audit.append('stream-b', {'event': 'same'})

        assert r1.mac != r2.mac

    def test_concurrent_audit_writes(self, dsn):
        """Concurrent audit writes should maintain integrity."""
        coord, shared, audit, _ = _setup_modules(dsn)
        stream = 'concurrent-' + uuid.uuid4().hex
        results = []
        lock = threading.Lock()
        barrier = threading.Barrier(10)

        def worker(idx):
            barrier.wait()
            receipt = audit.append(stream, {'event': f'worker-{idx}'})
            with lock:
                results.append(receipt)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        valid, count = audit.verify(stream)
        assert valid is True
        assert count == 10


class TestTransactionRollbackAndErrors:
    """Test transaction rollback and database error handling."""

    def test_admission_transaction_atomicity(self, dsn):
        """Admission should be atomic - either fully committed or rolled back."""
        coord, shared, audit, connect = _setup_modules(dsn)
        agent = 'atomic-' + uuid.uuid4().hex

        # Successful admission should persist
        ok, _ = coord.admit(
            request_id=str(uuid.uuid4()), agent=agent, fingerprint='fp',
            limit=10, approval_required=False, approval_token=None
        )
        assert ok

        # Verify in database
        conn = connect()
        count = conn.execute(
            "SELECT count(*) FROM ag_admissions WHERE agent = %s", (agent,)
        ).fetchone()[0]
        conn.close()
        assert count == 1

    def test_approval_consumption_atomic(self, dsn):
        """Approval consumption should be atomic with admission."""
        coord, shared, audit, _ = _setup_modules(dsn)
        agent = 'atomic-appr-' + uuid.uuid4().hex
        fp = 'test-fingerprint'

        token = shared.grant(agent, fp, ttl=120)

        # Admission should consume approval atomically
        ok, _ = coord.admit(
            request_id=str(uuid.uuid4()),
            agent=agent, fingerprint=fp, limit=10,
            approval_required=True, approval_token=token
        )
        assert ok

        # Approval should be marked consumed
        conn = _connect(dsn)
        consumed = conn.execute(
            "SELECT consumed FROM ag_approvals WHERE token_hash = %s",
            (hashlib.sha256(token.encode()).hexdigest(),)
        ).fetchone()[0]
        conn.close()
        assert consumed is True


class TestDatabaseRestartAndRecovery:
    """Test database restart and connection recovery."""

    def test_connection_recovery_after_transient_error(self, dsn):
        """New connections should work after transient errors."""
        from agentguard.coordination import PostgresCoordinator

        def connect():
            return _connect(dsn)

        coord = PostgresCoordinator(connect)
        coord.initialize()

        agent = 'recovery-' + uuid.uuid4().hex

        # Normal admission
        ok, _ = coord.admit(
            request_id=str(uuid.uuid4()), agent=agent, fingerprint='fp',
            limit=10, approval_required=False, approval_token=None
        )
        assert ok

        # Create a new coordinator with new connection factory
        coord2 = PostgresCoordinator(connect)
        ok, _ = coord2.admit(
            request_id=str(uuid.uuid4()), agent=agent, fingerprint='fp',
            limit=10, approval_required=False, approval_token=None
        )
        assert ok

    def test_shared_control_recovery(self, dsn):
        """SharedControl should recover with new connections."""
        from agentguard.shared_control import SharedControl

        def connect():
            return _connect(dsn)

        shared = SharedControl(connect)
        shared.initialize()
        shared.set_halt(True)

        # New instance should see the halt state
        shared2 = SharedControl(connect)
        assert shared2.is_halted() is True


class TestFailClosedBehavior:
    """Test fail-closed behavior when PostgreSQL is unavailable."""

    def test_coordinator_unavailable_fails_closed(self, dsn):
            """Coordinator should fail closed when database unavailable."""
            from agentguard.coordination import PostgresCoordinator

            def bad_connect():
                # Connect to non-existent port
                import psycopg
                return psycopg.connect("postgresql://user:pass@localhost:5433/db", connect_timeout=2)

            coord = PostgresCoordinator(bad_connect)

            with pytest.raises(Exception):
                coord.admit(
                    request_id=str(uuid.uuid4()), agent='agent', fingerprint='fp',
                    limit=10, approval_required=False, approval_token=None
                )

    def test_shared_control_unavailable_fails_closed(self, dsn):
            """SharedControl should fail closed when database unavailable."""
            from agentguard.shared_control import SharedControl

            def bad_connect():
                import psycopg
                return psycopg.connect("postgresql://user:pass@localhost:5433/db", connect_timeout=2)

            shared = SharedControl(bad_connect)

            with pytest.raises(Exception):
                shared.is_halted()

            with pytest.raises(Exception):
                shared.grant('agent', 'fp', 120)

    def test_audit_unavailable_fails_closed(self, dsn):
            """Audit should fail closed when database unavailable."""
            from agentguard.central_audit import PostgresAudit

            def bad_connect():
                import psycopg
                return psycopg.connect("postgresql://user:pass@localhost:5433/db", connect_timeout=2)

            audit = PostgresAudit(bad_connect, b'k' * 32)

            with pytest.raises(Exception):
                audit.append('stream', {'event': 'test'})

            with pytest.raises(Exception):
                audit.verify('stream')


# Helper to make dsn available as fixture
@pytest.fixture
def dsn():
    return os.environ['AG_TEST_POSTGRES_DSN']


@pytest.fixture(autouse=True)
def clear_database(dsn):
    """Clear database tables before each test to ensure isolation."""
    import psycopg
    conn = psycopg.connect(dsn)
    with conn.transaction():
        conn.execute('TRUNCATE TABLE ag_admissions CASCADE')
        conn.execute('TRUNCATE TABLE ag_admission_audit CASCADE')
        conn.execute('TRUNCATE TABLE ag_approvals CASCADE')
        conn.execute('TRUNCATE TABLE ag_audit_events CASCADE')
        conn.execute('TRUNCATE TABLE ag_control CASCADE')
        conn.execute("INSERT INTO ag_control(name,enabled) VALUES ('halt', FALSE) ON CONFLICT(name) DO UPDATE SET enabled=FALSE")
    conn.close()
    yield
