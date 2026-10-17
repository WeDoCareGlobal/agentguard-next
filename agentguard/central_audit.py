"""PostgreSQL append-only, per-stream HMAC chained audit log.

Requires PostgreSQL, a secret HMAC key, and DB permissions that prohibit UPDATE/DELETE
for the application role. External checkpoint anchoring is needed to detect tail truncation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass

DDL = '''
CREATE TABLE IF NOT EXISTS ag_audit_events (
 stream TEXT NOT NULL,
 sequence BIGINT NOT NULL,
 recorded_at DOUBLE PRECISION NOT NULL,
 event_json TEXT NOT NULL,
 prev_mac TEXT NOT NULL,
 mac TEXT NOT NULL,
 PRIMARY KEY(stream,sequence)
);
'''

def canonical_event(event: dict) -> str:
    if not isinstance(event, dict):
        raise TypeError('event must be an object')
    return json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)

def event_mac(key: bytes, stream: str, sequence: int, recorded_at: float, event_json: str, prev_mac: str) -> str:
    payload = json.dumps([stream, sequence, recorded_at, event_json, prev_mac], separators=(',', ':'), ensure_ascii=False)
    return hmac.new(key, payload.encode('utf-8'), hashlib.sha256).hexdigest()

@dataclass(frozen=True)
class AuditReceipt:
    stream: str
    sequence: int
    mac: str

class PostgresAudit:
    def __init__(self, connection_factory, key: bytes):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError('HMAC key must contain at least 32 bytes')
        self.connection_factory = connection_factory
        self.key = key

    def initialize(self):
        with self.connection_factory() as conn, conn.transaction():
            conn.execute(DDL)

    def append(self, stream: str, event: dict) -> AuditReceipt:
        if not stream or len(stream) > 200:
            raise ValueError('invalid stream')
        body = canonical_event(event)
        timestamp = time.time()
        lock_id = int.from_bytes(hashlib.sha256(('audit:'+stream).encode()).digest()[:8], 'big', signed=True)
        with self.connection_factory() as conn:
            with conn.transaction():
                conn.execute('SELECT pg_advisory_xact_lock(%s)', (lock_id,))
                row = conn.execute('SELECT sequence,mac FROM ag_audit_events WHERE stream=%s ORDER BY sequence DESC LIMIT 1', (stream,)).fetchone()
                seq, previous = (row[0]+1, row[1]) if row else (1, '0'*64)
                mac = event_mac(self.key, stream, seq, timestamp, body, previous)
                conn.execute('INSERT INTO ag_audit_events(stream,sequence,recorded_at,event_json,prev_mac,mac) VALUES (%s,%s,%s,%s,%s,%s)', (stream,seq,timestamp,body,previous,mac))
                return AuditReceipt(stream, seq, mac)

    def verify(self, stream: str) -> tuple[bool, int]:
        with self.connection_factory() as conn:
            with conn.transaction():
                rows = conn.execute('SELECT sequence,recorded_at,event_json,prev_mac,mac FROM ag_audit_events WHERE stream=%s ORDER BY sequence', (stream,)).fetchall()
        previous = '0'*64
        for expected, (seq, timestamp, body, prev, mac) in enumerate(rows, 1):
            if seq != expected or not hmac.compare_digest(prev, previous):
                return False, expected-1
            calculated = event_mac(self.key, stream, seq, timestamp, body, prev)
            if not hmac.compare_digest(calculated, mac):
                return False, expected-1
            previous = mac
        return True, len(rows)
