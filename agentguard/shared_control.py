"""PostgreSQL shared controls. All state changes use database transactions.

Requires a connection factory yielding an independent psycopg connection per call.
Do not use a shared connection concurrently across workers.
"""
from __future__ import annotations

import hashlib
import secrets
import time

DDL = '''
CREATE TABLE IF NOT EXISTS ag_control (name TEXT PRIMARY KEY, enabled BOOLEAN NOT NULL);
CREATE TABLE IF NOT EXISTS ag_approvals (
 token_hash TEXT PRIMARY KEY, agent TEXT NOT NULL, payload_hash TEXT NOT NULL,
 expires DOUBLE PRECISION NOT NULL, consumed BOOLEAN NOT NULL DEFAULT FALSE
);
'''

class SharedControl:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    def initialize(self):
        with self.connection_factory() as conn, conn.transaction():
            for statement in DDL.split(';'):
                if statement.strip(): conn.execute(statement)

    def set_halt(self, enabled: bool):
        with self.connection_factory() as conn:
            with conn.transaction():
                conn.execute('INSERT INTO ag_control(name,enabled) VALUES (%s,%s) ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled', ('halt', enabled))

    def is_halted(self) -> bool:
        with self.connection_factory() as conn:
            row = conn.execute('SELECT enabled FROM ag_control WHERE name=%s', ('halt',)).fetchone()
            return bool(row[0]) if row else False

    def grant(self, agent: str, payload_hash: str, ttl: int = 120) -> str:
        if not agent or not payload_hash or not 1 <= ttl <= 3600:
            raise ValueError('Invalid approval')
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.connection_factory() as conn:
            with conn.transaction():
                conn.execute('INSERT INTO ag_approvals(token_hash,agent,payload_hash,expires) VALUES (%s,%s,%s,%s)', (digest, agent, payload_hash, time.time()+ttl))
        return token

    def consume(self, agent: str, payload_hash: str, token: str | None) -> bool:
        if not token or not agent or not payload_hash: return False
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.connection_factory() as conn, conn.transaction():
            row = conn.execute('''UPDATE ag_approvals SET consumed=TRUE
                    WHERE token_hash=%s AND agent=%s AND payload_hash=%s
                    AND expires>%s AND consumed=FALSE RETURNING token_hash''',
                (digest,agent,payload_hash,time.time())).fetchone()
            return row is not None
