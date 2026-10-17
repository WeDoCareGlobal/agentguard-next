"""Tests for the 4-Layer Verification Engine (Step 4)."""

import hashlib
import hmac
import time
import unittest
from agentguard.verification import (
    PolicyVerifier,
    AnomalyVerifier,
    IntentVerifier,
    ProofVerifier,
    VerificationEngine,
)


class TestPolicyLayer(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyVerifier(
            allowed_tools=frozenset({"read", "write"}),
            denied_tools=frozenset({"blocked"}),
            approval_required=frozenset({"write"}),
        )

    def test_allowed_tool(self):
        r = self.policy.verify("a", "read")
        self.assertTrue(r.allowed)
        self.assertLess(r.latency_ms, 5.0)
        self.assertEqual(r.layer, "policy")

    def test_denied_tool(self):
        r = self.policy.verify("a", "blocked")
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "tool_denied")

    def test_approval_required(self):
        r = self.policy.verify("a", "write")
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "approval_required")


class TestAnomalyLayer(unittest.TestCase):
    def setUp(self):
        self.anomaly = AnomalyVerifier(call_window_seconds=5.0, max_calls_per_window=50)

    def test_clean_request(self):
        r = self.anomaly.verify("a", "read", {"q": "hello"})
        self.assertTrue(r.allowed)
        self.assertLess(r.latency_ms, 15.0)

    def test_empty_payload_blocked(self):
        r = self.anomaly.verify("a", "read", {})
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "empty_payload_probe")

    def test_loop_detection(self):
        for _ in range(11):
            self.anomaly.verify("a", "read", {"q": "test"})
        r = self.anomaly.verify("a", "read", {"q": "x"})
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "loop_or_spam")


class TestIntentLayer(unittest.TestCase):
    def setUp(self):
        self.intent = IntentVerifier()

    def test_intent_classification(self):
        r = self.intent.verify("a", "read", {"q": "hello"})
        self.assertTrue(r.allowed)
        self.assertLess(r.latency_ms, 800.0)

    def test_intent_consent_required(self):
        # data_mutate tools require an explicit consent token
        r = self.intent.verify("a", "write", {"payload": "docs"})
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "intent_requires_consent")


class TestProofLayer(unittest.TestCase):
    def setUp(self):
        self.proof = ProofVerifier(b"k" * 32)

    def test_valid_proof(self):
        # Generate a valid deterministic proof for this agent/tool/payload
        payload = {"x": 1}
        data = f"a|read|{hashlib.sha256(str(payload).encode()).hexdigest()}".encode()
        expected = hmac.new(self.proof.key, data, hashlib.sha256).hexdigest()[:32]
        r = self.proof.verify("a", "read", payload, proof=expected + "0" * 32)
        self.assertTrue(r.allowed)

    def test_invalid_proof(self):
        r = self.proof.verify("a", "read", {"x": 1}, proof="f" * 64)
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "proof_mismatch")

    def test_missing_proof(self):
        r = self.proof.verify("a", "read", {"x": 1}, proof="")
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "missing_proof")


class TestFullVerificationEngine(unittest.TestCase):
    def setUp(self):
        self.policy = PolicyVerifier(
            allowed_tools=frozenset({"read", "write"}),
            denied_tools=frozenset({"blocked"}),
            approval_required=frozenset({"write"}),
        )
        self.anomaly = AnomalyVerifier()
        self.intent = IntentVerifier()
        self.proof = ProofVerifier(b"k" * 32)
        self.engine = VerificationEngine(self.policy, self.anomaly, self.intent, self.proof)

    def test_full_allow(self):
        # Full end-to-end allow: all 4 layers pass
        payload = {"q": "hello"}
        agent, tool = "a", "read"
        # Generate a valid proof for this specific agent/tool/payload
        data = f"{agent}|{tool}|{hashlib.sha256(str(payload).encode()).hexdigest()}".encode()
        expected = hmac.new(self.proof.key, data, hashlib.sha256).hexdigest()[:32]
        valid_proof = expected + "0" * 32
        bundle = self.engine.verify(agent, tool, payload, proof=valid_proof)
        self.assertEqual(bundle.overall_decision, "ALLOW")
        self.assertTrue(bundle.all_allowed)

    def test_first_deny_wins(self):
        # Policy denies
        bundle = self.engine.verify("a", "blocked", {"q": "hello"}, proof="0" * 64)
        self.assertEqual(bundle.overall_decision, "DENY")
        self.assertEqual(bundle.blocked_reason, "tool_denied")

    def test_layer_ordering(self):
        bundle = self.engine.verify("a", "read", {}, proof="0" * 64)
        # Layer 1 passes, Layer 2 (anomaly) catches empty payload
        self.assertEqual(bundle.overall_decision, "DENY")
        self.assertEqual(bundle.blocked_reason, "empty_payload_probe")

    def test_intent_layer_timing(self):
        bundle = self.engine.verify("a", "read", {"q": "hello"}, proof="0" * 64)
        # Intent layer (300-800ms) is the slowest; intent_ms should reflect that
        self.assertLess(bundle.intent.latency_ms, 800.0)
        self.assertGreater(bundle.intent.latency_ms, 200.0)
