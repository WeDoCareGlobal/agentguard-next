"""Atomic PostgreSQL admission: shared halt, replay, rate and approval.

Admission is durable; tool execution is outside the DB transaction. A reservation
is never rolled back after a tool failure, to avoid unsafe duplicate execution.
"""
from __future__ import annotations

import hashlib
import time

DDL = '''
CREATE TABLE IF NOT EXISTS ag_admissions (
 request_id TEXT PRIMARY KEY, agent TEXT NOT NULL, fingerprint TEXT NOT NULL,
 created_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS ag_admissions_agent_time ON ag_admissions(agent,created_at);
CREATE TABLE IF NOT EXISTS ag_admission_audit (
 id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 request_id TEXT NOT NULL, agent TEXT NOT NULL, decision TEXT NOT NULL,
 recorded_at DOUBLE PRECISION NOT NULL
);
'''

class PostgresCoordinator:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    def initialize(self):
        with self.connection_factory() as conn, conn.transaction():
            for stmt in DDL.split(';'):
                if stmt.strip(): conn.execute(stmt)

    def admit(self, *, request_id: str, agent: str, fingerprint: str,
              limit: int, approval_required: bool, approval_token: str | None) -> tuple[bool, str]:
        if not request_id or len(request_id)>200 or not agent or not fingerprint or limit<1:
            return False, 'invalid_request'
        now = time.time()
        lock_id = int.from_bytes(hashlib.sha256(agent.encode()).digest()[:8], 'big', signed=True)
        with self.connection_factory() as conn, conn.transaction():
            conn.execute('SELECT pg_advisory_xact_lock(%s)', (lock_id,))
            halted = conn.execute('SELECT enabled FROM ag_control WHERE name=%s', ('halt',)).fetchone()
            if halted and halted[0]: return False, 'kill_switch'
            if conn.execute('SELECT 1 FROM ag_admissions WHERE request_id=%s', (request_id,)).fetchone():
                return False, 'replay'
            count = conn.execute('SELECT count(*) FROM ag_admissions WHERE agent=%s AND created_at>%s', (agent, now-60)).fetchone()[0]
            if count >= limit: return False, 'rate_limit'
            if approval_required:
                if not approval_token: return False, 'approval_missing_or_invalid'
                digest = hashlib.sha256(approval_token.encode()).hexdigest()
                row = conn.execute('''UPDATE ag_approvals SET consumed=TRUE WHERE token_hash=%s
                    AND agent=%s AND payload_hash=%s AND expires>%s AND consumed=FALSE
                    RETURNING token_hash''', (digest, agent, fingerprint, now)).fetchone()
                if row is None: return False, 'approval_missing_or_invalid'
                conn.execute('INSERT INTO ag_admissions(request_id,agent,fingerprint,created_at) VALUES (%s,%s,%s,%s)',(request_id,agent,fingerprint,now))
                conn.execute('INSERT INTO ag_admission_audit(request_id,agent,decision,recorded_at) VALUES (%s,%s,%s,%s)',(request_id,agent,'ADMITTED',now))
                return True, 'admitted'
            return True, 'admitted'
