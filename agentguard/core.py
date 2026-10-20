"""Explicitly registered, fail-closed tool execution with durable SQLite decisions.

Single-process reference implementation. Not suitable for distributed production.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def fingerprint(agent: str, tool: str, payload: Any) -> str:
    return hashlib.sha256(canonical({"agent": agent, "tool": tool, "payload": payload}).encode()).hexdigest()


@dataclass(frozen=True)
class Policy:
    allowed: frozenset[str] = frozenset()
    denied: frozenset[str] = frozenset()
    approval_required: frozenset[str] = frozenset()

    def decide(self, tool: str) -> str:
        if not tool or tool in self.denied or tool not in self.allowed:
            return "DENY"
        if tool in self.approval_required:
            return "APPROVAL_REQUIRED"
        return "ALLOW"


class Guard:
    def __init__(
        self,
        db_path: str,
        audit_key: bytes,
        policy: Policy,
        tools: dict[str, Callable[[Any], Any]],
        max_per_minute: int = 60,
        reservation_store=None,
        shared_control=None,
        coordinator=None,
        central_audit=None,
    ):
        if not audit_key or len(audit_key) < 32:
            raise ValueError("Audit key must be at least 32 bytes")
        if max_per_minute < 1:
            raise ValueError("max_per_minute must be positive")
        self.key, self.policy, self.tools = audit_key, policy, dict(tools)
        self.max_per_minute = max_per_minute
        self.reservation_store = reservation_store
        self.shared_control = shared_control
        self.coordinator = coordinator
        self.central_audit = central_audit
        self.lock = threading.RLock()
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL, previous TEXT NOT NULL, signature TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS requests (request_id TEXT PRIMARY KEY, agent TEXT NOT NULL, fingerprint TEXT NOT NULL, outcome TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS approvals (token_hash TEXT PRIMARY KEY, agent TEXT NOT NULL, fingerprint TEXT NOT NULL, expires REAL NOT NULL, used INTEGER NOT NULL DEFAULT 0)")
        self.db.execute("CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS calls (agent TEXT NOT NULL, at REAL NOT NULL)")

    def _audit(self, data: dict[str, Any]) -> None:
        body = canonical({"timestamp": time.time(), **data})
        row = self.db.execute("SELECT signature FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        previous = row[0] if row else "GENESIS"
        sig = hmac.new(self.key, (previous + body).encode(), hashlib.sha256).hexdigest()
        self.db.execute("INSERT INTO events(body, previous, signature) VALUES(?,?,?)", (body, previous, sig))

    def audit_status(self) -> dict[str, Any]:
        """Local chain status plus optional central verification; errors are unhealthy."""
        with self.lock:
            local = self.verify_audit()
            count = self.db.execute("SELECT count(*) FROM events").fetchone()[0]
            central = None
            if self.central_audit is not None:
                            try:
                                valid, checked = self.central_audit.verify("enforcement")
                                central = {"valid": bool(valid), "checked": checked}
                            except Exception as exc:  # noqa: BLE001 - central audit unavailable, fail closed
                                central = {"valid": False, "error": f"unavailable: {exc}"}
            return {"local_valid": local, "local_events": count, "central": central,
                    "healthy": local and (central is None or central.get("valid") is True)}

    def verify_audit(self) -> bool:
        with self.lock:
            previous = "GENESIS"
            expected_seq = 1
            for seq, body, prev, signature in self.db.execute("SELECT seq, body, previous, signature FROM events ORDER BY seq"):
                expected = hmac.new(self.key, (previous + body).encode(), hashlib.sha256).hexdigest()
                if seq != expected_seq or prev != previous or not hmac.compare_digest(signature, expected):
                    return False
                previous = signature
                expected_seq += 1
            return True

    def set_kill_switch(self, enabled: bool) -> None:
        with self.lock:
            if self.shared_control is not None:
                self.shared_control.set_halt(enabled)
            self.db.execute("INSERT INTO settings(name,value) VALUES('halt',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value", ("1" if enabled else "0",))
            self._audit({"event": "kill_switch", "enabled": enabled})

    def grant(self, agent: str, tool: str, payload: Any, ttl: int = 120) -> str:
        if not agent or ttl < 1 or ttl > 3600 or self.policy.decide(tool) != "APPROVAL_REQUIRED" or tool not in self.tools:
            raise ValueError("Invalid approval request")
        with self.lock:
            if not self.verify_audit():
                raise RuntimeError("audit_integrity_failure")
        if self.shared_control is not None:
            return self.shared_control.grant(agent, fingerprint(agent, tool, payload), ttl)
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.db.execute("INSERT INTO approvals(token_hash,agent,fingerprint,expires) VALUES(?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), agent, fingerprint(agent, tool, payload), time.time() + ttl))
            self._audit({"event": "approval_issued", "agent": agent, "tool": tool})
        return token

    def execute(self, agent: str, tool: str, payload: Any, request_id: str, approval: str | None = None) -> dict[str, Any]:
        if not agent or not tool or not request_id or len(request_id) > 200:
            return {"decision": "DENY", "reason": "invalid_request"}
        try:
            fp = fingerprint(agent, tool, payload)
        except (TypeError, ValueError):
            return {"decision": "DENY", "reason": "invalid_payload"}
        with self.lock:
            # Corrupt local evidence must block admission before tokens, reservations,
            # or tools are consumed. Do not append to a chain known to be corrupt.
            if not self.verify_audit():
                return {"decision": "DENY", "reason": "audit_integrity_failure"}
            if self.db.execute("SELECT 1 FROM requests WHERE request_id=?", (request_id,)).fetchone():
                self._audit({"event": "replay_blocked", "request_id": request_id})
                return {"decision": "DENY", "reason": "replay"}
            decision = self.policy.decide(tool)
            reason = "policy"
            try:
                halted = self.shared_control.is_halted() if self.shared_control is not None else self.db.execute("SELECT value FROM settings WHERE name='halt'").fetchone() == ("1",)
            except Exception as exc:  # noqa: BLE001 - shared control unavailable, fail closed
                log.warning("Shared control unavailable, failing closed: %s", exc)
                halted = True  # Shared control unavailable: fail closed.
            if halted:
                decision, reason = "DENY", "kill_switch"
            elif tool not in self.tools:
                decision, reason = "DENY", "unregistered_tool"
            # Preflight local rate limit before consuming a one-time approval.
            # This is an in-process mitigation, not a distributed transaction.
            if decision in ("ALLOW", "APPROVAL_REQUIRED") and self.coordinator is None and self.reservation_store is None:
                now = time.time()
                self.db.execute("DELETE FROM calls WHERE at < ?", (now - 60,))
                count = self.db.execute("SELECT count(*) FROM calls WHERE agent=?", (agent,)).fetchone()[0]
                if count >= self.max_per_minute:
                    decision, reason = "DENY", "rate_limit"
            if decision == "APPROVAL_REQUIRED" and self.coordinator is None:
                if self.shared_control is not None:
                    try:
                        approved = self.shared_control.consume(agent, fp, approval)
                    except Exception as exc:  # noqa: BLE001 - shared control unavailable, fail closed
                        log.warning("Shared control consume failed: %s", exc)
                        approved = False
                else:
                    token_hash = hashlib.sha256((approval or "").encode()).hexdigest()
                    row = self.db.execute("SELECT agent,fingerprint,expires,used FROM approvals WHERE token_hash=?", (token_hash,)).fetchone()
                    approved = bool(row and row[0] == agent and hmac.compare_digest(row[1], fp) and row[2] > time.time() and row[3] == 0)
                    if approved:
                        self.db.execute("UPDATE approvals SET used=1 WHERE token_hash=? AND used=0", (token_hash,))
                if approved:
                    decision = "ALLOW"
                else:
                    reason = "approval_missing_or_invalid"
            if self.coordinator is not None and decision in ("ALLOW", "APPROVAL_REQUIRED"):
                try:
                    admitted, reason = self.coordinator.admit(
                        request_id=request_id, agent=agent, fingerprint=fp,
                        limit=self.max_per_minute,
                        approval_required=decision == "APPROVAL_REQUIRED",
                        approval_token=approval)
                except Exception as exc:  # noqa: BLE001 - coordinator unavailable, fail closed
                    log.warning("Coordinator admit failed: %s", exc)
                    admitted, reason = False, "coordination_unavailable"
                decision = "ALLOW" if admitted else "DENY"
            if decision == "ALLOW" and self.coordinator is None and self.reservation_store is not None:
                # Cross-worker replay/rate-limit reservation. Fail closed on DB errors.
                # A reservation is not refunded if local execution subsequently fails.
                try:
                    reserved = self.reservation_store.reserve(request_id, agent, fp, self.max_per_minute)
                except Exception as exc:  # noqa: BLE001 - reservation store unavailable, fail closed
                    log.warning("Reservation store failed: %s", exc)
                    reserved = False
                    reason = "coordination_unavailable"
                if not reserved:
                    decision = "DENY"
                    if reason != "coordination_unavailable":
                        reason = "distributed_replay_or_rate_limit"
            if decision == "ALLOW" and self.coordinator is None:
                now = time.time()
                self.db.execute("DELETE FROM calls WHERE at < ?", (now - 60,))
                count = self.db.execute("SELECT count(*) FROM calls WHERE agent=?", (agent,)).fetchone()[0]
                if count >= self.max_per_minute:
                    decision, reason = "DENY", "rate_limit"
                else:
                    self.db.execute("INSERT INTO calls(agent,at) VALUES(?,?)", (agent, now))
            if self.central_audit is not None:
                try:
                    self.central_audit.append("enforcement", {"event": "decision", "agent": agent, "tool": tool, "request_id": request_id, "decision": decision, "reason": reason})
                except Exception as exc:  # noqa: BLE001 - central audit unavailable, fail closed
                    log.warning("Central audit append failed: %s", exc)
                    # Never execute when the required centralized audit is unavailable.
                    decision, reason = "DENY", "central_audit_unavailable"
            self.db.execute("INSERT INTO requests(request_id,agent,fingerprint,outcome) VALUES(?,?,?,?)", (request_id, agent, fp, decision))
            self._audit({"event": "decision", "agent": agent, "tool": tool, "request_id": request_id, "decision": decision, "reason": reason})
            if decision != "ALLOW":
                return {"decision": decision, "reason": reason}
            # Serialize tool invocation in this reference implementation to avoid in-process races.
            try:
                result = self.tools[tool](payload)
                if self.central_audit is not None:
                    try:
                        self.central_audit.append("enforcement", {"event": "execution_completed", "request_id": request_id})
                    except Exception as exc:  # noqa: BLE001 - central audit unavailable, fail closed
                        log.warning("Central audit append failed after execution: %s", exc)
                        self._audit({"event": "central_audit_failed_after_execution", "request_id": request_id})
                        return {"decision": "ERROR", "reason": "central_audit_unavailable_after_execution"}
                self._audit({"event": "execution_completed", "request_id": request_id})
                return {"decision": "ALLOW", "result": result}
            except Exception:  # noqa: BLE001 - tool execution failed, fail closed
                if self.central_audit is not None:
                    try:
                        self.central_audit.append("enforcement", {"event": "execution_failed", "request_id": request_id})
                    except Exception as exc2:  # noqa: BLE001 - central audit unavailable for execution_failed, fail closed
                        log.warning("Central audit append failed for execution_failed: %s", exc2)
                self._audit({"event": "execution_failed", "request_id": request_id})
                return {"decision": "ERROR", "reason": "tool_execution_failed"}
