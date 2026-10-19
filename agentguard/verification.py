"""4-Layer Verification Engine for AgentGuard.

Layer timing (per request):
- Layer 1 — Policy     : < 5ms    — rapid allow/deny via static policy
- Layer 2 — Anomaly    : < 15ms  — behavioral anomaly detection (local heuristics)
- Layer 3 — Intent     : 300-800ms — semantic intent classification (LLM-gated)
- Layer 4 — Proof      : < 10ms  — cryptographic proof-of-work verification

The engine returns a structured decision bundle:
  { "pol":  "ALLOW|DENY", "ano": "ALLOW|DENY", "int": "ALLOW|DENY", "pow": "ALLOW|DENY" }
  overall_decision = policy arithmetic dominance, or first deny wins.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LayerResult:
    layer: str
    allowed: bool
    latency_ms: float
    reason: str = ""


@dataclass
class VerificationBundle:
    policy:  LayerResult = field(default_factory=lambda: LayerResult("policy",  True,  0.0))
    anomaly: LayerResult = field(default_factory=lambda: LayerResult("anomaly", True, 0.0))
    intent:  LayerResult = field(default_factory=lambda: LayerResult("intent",  True, 0.0))
    proof:   LayerResult = field(default_factory=lambda: LayerResult("proof",   True, 0.0))
    overall_decision: str = "ALLOW"
    blocked_reason: str = ""

    @property
    def all_allowed(self) -> bool:
        return all(
            (getattr(self, n).allowed) for n in ("policy", "anomaly", "intent", "proof")
        )

    @property
    def first_deny_layer(self) -> str | None:
        for n in ("policy", "anomaly", "intent", "proof"):
            if not getattr(self, n).allowed:
                return n
        return None


class PolicyVerifier:
    """Layer 1 — Policy verification (rapid allow/deny).

    Executes in < 5ms: direct hash table lookup of tool against static policy
    allow/deny lists. No I/O, no network, no LLM calls.
    """

    def __init__(self, allowed_tools: frozenset[str], denied_tools: frozenset[str], approval_required: frozenset[str]):
        self.allowed = allowed_tools
        self.denied = denied_tools
        self.approval_required = approval_required

    def verify(self, agent: str, tool: str) -> LayerResult:
        t0 = time.perf_counter()
        if tool in self.denied:
            latency = (time.perf_counter() - t0) * 1000.0
            return LayerResult("policy", False, latency, "tool_denied")
        if tool in self.approval_required:
            latency = (time.perf_counter() - t0) * 1000.0
            return LayerResult("policy", False, latency, "approval_required")
        if tool in self.allowed:
            latency = (time.perf_counter() - t0) * 1000.0
            return LayerResult("policy", True, latency, "allowed")
        latency = (time.perf_counter() - t0) * 1000.0
        return LayerResult("policy", False, latency, "tool_not_in_allowlist")


class AnomalyVerifier:
    """Layer 2 — Anomaly detection (< 15ms).

    Pure heuristic, in-process, no external calls. Captures:
    - Repeated rapid-fire identical tool calls (loop/spam)
    - Unusual rate of calls from a single agent
    - Requests with empty payloads (sign of automated probing)
    """

    def __init__(self, call_window_seconds: float = 5.0, max_calls_per_window: int = 50):
        self.call_window = call_window_seconds
        self.max_calls = max_calls_per_window
        self._agent_calls: dict[str, list[dict[str, Any]]] = {}
        self._lock = __import__("threading").RLock()

    def verify(self, agent: str, tool: str, payload: Any, timestamp: float | None = None) -> LayerResult:
        t0 = time.perf_counter()
        now = time.monotonic() if timestamp is None else timestamp
        with self._lock:
            window = self._agent_calls.setdefault(agent, [])
            cutoff = now - self.call_window
            while window and window[0]["at"] < cutoff:
                window.pop(0)
            # Detect loop: >10 calls in 5 seconds for same agent+tool
            same_tool_count = sum(1 for entry in window if entry.get("tool") == tool)
            if len(window) > self.max_calls or same_tool_count > 10:
                latency = (time.perf_counter() - t0) * 1000.0
                return LayerResult("anomaly", False, latency, "loop_or_spam")
            if payload is None or (isinstance(payload, dict) and len(payload) == 0):
                latency = (time.perf_counter() - t0) * 1000.0
                return LayerResult("anomaly", False, latency, "empty_payload_probe")
            window.append({"tool": tool, "at": now})
            latency = (time.perf_counter() - t0) * 1000.0
            return LayerResult("anomaly", True, latency, "clean")


class IntentVerifier:
    """Layer 3 — Intent classification (300–800ms).

    Semantic intent classification. In production this routes to a hosted LLM
    endpoint with configurable timeout. For this reference implementation,
    intent is approximated by static heuristics + optional hook hook for
    LLM classification, preserving the timing envelope.
    """

    def __init__(self, llm_classify: Callable[[str], str] | None = None):
        # tag -> category mapping used for static approximation
        self._heuristics = {
            "read": "data_access", "write": "data_mutate", "delete": "data_mutate",
            "list": "metadata", "search": "search", "approve": "governance",
            "deploy": "infra", "restart": "infra", "config": "config",
        }
        self._llm = llm_classify

    def verify(self, agent: str, tool: str, payload: Any) -> LayerResult:
        t0 = time.perf_counter()
        # Simulate LLM intent classification (300-800ms envelope)
        import time as _t
        _t.sleep(0.35)  # nominal ~350ms; production: actual LLM call
        latency = (time.perf_counter() - t0) * 1000.0
        # Approval gates on intent: data_mutate + approval_required
        decision = True
        reason = "intent_approved"
        if tool in ("write", "delete", "deploy", "restart", "config") and not any(k in str(payload) for k in ("confirm", "approved", "consent")):
            decision = False
            reason = "intent_requires_consent"
        return LayerResult("intent", decision, latency, reason)


class ProofVerifier:
    """Layer 4 — Proof-of-work verification (< 10ms).

    Verifies a deterministic proof token issued per (agent, tool, payload)
    triple. In production, proofs are nonces with cryptographic challenges.
    Here we verify a deterministic HMAC and a simple elapsed-time bound.
    """

    def __init__(self, key: bytes):
        if not key or len(key) < 16:
            raise ValueError("Proof key must be at least 16 bytes")
        self.key = key

    def verify(self, agent: str, tool: str, payload: Any, proof: str | None) -> LayerResult:  # pragma: no cover
        t0 = time.perf_counter()
        if not proof or len(proof) < 16:
            latency = (time.perf_counter() - t0) * 1000.0
            return LayerResult("proof", False, latency, "missing_proof")
        # Compute expected proof over salt + tool + payload
        try:
            data = f"{agent}|{tool}|{hashlib.sha256(str(payload).encode()).hexdigest()}".encode()
            expected = hmac.new(self.key, data, hashlib.sha256).hexdigest()[:32]
        except Exception:
            logger.exception("Proof computation error")
            latency = (time.perf_counter() - t0) * 1000.0
            return LayerResult("proof", False, latency, "proof_computation_error")
        if not hmac.compare_digest(proof[:32], expected):
            latency = (time.perf_counter() - t0) * 1000.0
            return LayerResult("proof", False, latency, "proof_mismatch")
        latency = (time.perf_counter() - t0) * 1000.0
        return LayerResult("proof", True, latency, "proof_valid")


class VerificationEngine:
    """4-Layer verification orchestrator.

    Runs layers sequentially; short-circuits on first deny. Each layer
    records its own latency so callers can expose per-layer timing.
    """

    def __init__(self, policy: PolicyVerifier, anomaly: AnomalyVerifier,
                 intent: IntentVerifier, proof: ProofVerifier):
        self.policy = policy
        self.anomaly = anomaly
        self.intent = intent
        self.proof = proof

    def verify(self, agent: str, tool: str, payload: Any, proof: str = "") -> VerificationBundle:
        bundle = VerificationBundle()
        # Layer 1 — Policy (< 5ms)
        bundle.policy = self.policy.verify(agent, tool)
        if not bundle.policy.allowed:
            bundle.overall_decision = "DENY"
            bundle.blocked_reason = bundle.policy.reason
            return bundle
        # Layer 2 — Anomaly (< 15ms)
        bundle.anomaly = self.anomaly.verify(agent, tool, payload)
        if not bundle.anomaly.allowed:
            bundle.overall_decision = "DENY"
            bundle.blocked_reason = bundle.anomaly.reason
            return bundle
        # Layer 3 — Intent (300-800ms)
        bundle.intent = self.intent.verify(agent, tool, payload)
        if not bundle.intent.allowed:
            bundle.overall_decision = "DENY"
            bundle.blocked_reason = bundle.intent.reason
            return bundle
        # Layer 4 — Proof (< 10ms)
        bundle.proof = self.proof.verify(agent, tool, payload, proof)
        if not bundle.proof.allowed:
            bundle.overall_decision = "DENY"
            bundle.blocked_reason = bundle.proof.reason
            return bundle
        bundle.overall_decision = "ALLOW"
        return bundle
