"""PostgreSQL-backed atomic replay and rate-limit reservation primitive.

Requires psycopg 3; the caller must provide a trusted, configured connection.
This does NOT replace Guard's SQLite audit/approval implementation.
"""
from __future__ import annotations

import hashlib
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS guard_reservations (
 request_id TEXT PRIMARY KEY,
 agent TEXT NOT NULL,
 payload_hash TEXT NOT NULL,
 created_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS guard_reservations_agent_time
 ON guard_reservations (agent, created_at);
"""

class PostgresReservationStore:
    def __init__(self, connection):
        self.connection = connection

    def initialize(self):
        with self.connection.transaction():
            for statement in SCHEMA.split(';'):
                if statement.strip():
                    self.connection.execute(statement)

    def reserve(self, request_id: str, agent: str, payload_hash: str, limit: int, now: float | None = None) -> bool:
        """Reserve at most `limit` calls per 60 seconds per agent across workers.

        Advisory transaction lock serializes concurrent requests for the same agent.
        False means replay, rate-limit, or invalid input; DB errors fail by raising.
        """
        if not request_id or not agent or not payload_hash or limit < 1 or len(request_id) > 200:
            return False
        timestamp = time.time() if now is None else now
        lock_id = int.from_bytes(hashlib.sha256(agent.encode()).digest()[:8], 'big', signed=True)
        with self.connection.transaction():
            self.connection.execute('SELECT pg_advisory_xact_lock(%s)', (lock_id,))
            existing = self.connection.execute('SELECT 1 FROM guard_reservations WHERE request_id=%s', (request_id,)).fetchone()
            if existing:
                return False
            count = self.connection.execute(
                'SELECT count(*) FROM guard_reservations WHERE agent=%s AND created_at > %s',
                (agent, timestamp - 60),
            ).fetchone()[0]
            if count >= limit:
                return False
            self.connection.execute(
                'INSERT INTO guard_reservations(request_id,agent,payload_hash,created_at) VALUES (%s,%s,%s,%s)',
                (request_id, agent, payload_hash, timestamp),
            )
            return True
