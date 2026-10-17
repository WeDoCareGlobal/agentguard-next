"""Tests for the Nous Portal per-tool gateway with credential isolation (Step 6)."""

import time
import unittest
from agentguard.nous_portal import NousPortalRouter, ProviderConfig
from agentguard.nous_portal_gateway import (
    PerToolGateway,
    create_per_tool_gateway,
    ToolCredential,
)


class TestToolCredential(unittest.TestCase):
    def setUp(self):
        self.router = NousPortalRouter(
            [ProviderConfig(name="nvidia-nim", base_url="https://nvidia.example.com/v1", model="llama-3.1-nemotron")]
        )
        self.master_key = "d" * 32
        self.salt = b"test-salt"
        self.gateway = PerToolGateway(
            router=self.router,
            tool_policy={
                "read": {"provider": "nvidia-nim", "ttl": 60},
                "write": {"provider": "nvidia-nim", "ttl": 30},
            },
            master_key=self.master_key,
            key_derivation_salt=self.salt,
        )

    def test_issue_and_validate_valid_credential(self):
        cred = self.gateway.issue_credential("read", "nvidia-nim")
        self.assertTrue(self.gateway.validate_credential(cred))
        self.assertEqual(cred.tool, "read")
        self.assertEqual(cred.provider, "nvidia-nim")
        self.assertGreater(cred.expires_at, time.monotonic())

    def test_invalid_document_id_key_rejected(self):
        cred = self.gateway.issue_credential("read", "nvidia-nim")
        # Tamper with the scoped key
        tampered = ToolCredential(
            tool=cred.tool, provider=cred.provider,
            scoped_key="f" * 32, expires_at=cred.expires_at,
            fingerprint=cred.fingerprint,
        )
        self.assertFalse(self.gateway.validate_credential(tampered))

    def test_expired_credential_rejected(self):
        cred = self.gateway.issue_credential("read", "nvidia-nim", ttl_seconds=1)
        # Wait for expiry
        time.sleep(1.1)
        self.assertFalse(self.gateway.validate_credential(cred))

    def test_unknown_tool_rejected(self):
        with self.assertRaises(ValueError):
            self.gateway.issue_credential("nonexistent", "nvidia-nim")


class TestPerToolGateway(unittest.TestCase):
    def setUp(self):
        self.router = NousPortalRouter(
            [ProviderConfig(name="nvidia-nim", base_url="https://nvidia.example.com/v1", model="llama-3.1-nemotron")]
        )
        self.master_key = "d" * 32
        self.salt = b"test-salt"
        self.gateway = PerToolGateway(
            router=self.router,
            tool_policy={
                "read": {"provider": "nvidia-nim", "model": "llama-3.1-nemotron", "ttl": 60},
                "write": {"provider": "nvidia-nim", "model": "llama-3.1-nemotron", "ttl": 30},
            },
            master_key=self.master_key,
            key_derivation_salt=self.salt,
        )

    def test_route_tool_call(self):
        tool_cred = self.gateway.issue_credential("read", "nvidia-nim")
        decision = self.gateway.route_tool_call(
            "read", {"q": "hello"}, "emir", tool_cred
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.provider, "nvidia-nim")
        self.assertEqual(decision.model, "llama-3.1-nemotron")
        self.assertEqual(decision.reason, "per-tool_gateway")
        self.assertGreater(decision.latency_ms, 0)

    def test_invalid_credential_rejected(self):
        invalid = ToolCredential(
            tool="read", provider="nvidia-nim",
            scoped_key="f" * 32, expires_at=time.monotonic() + 3600,
            fingerprint="abcd1234",
        )
        decision = self.gateway.route_tool_call(
            "read", {"q": "hello"}, "emir", invalid
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "invalid_or_expired_credential")

    def test_tool_policy_content(self):
        tools = self.gateway.get_available_tools()
        self.assertIn("read", tools)
        self.assertIn("write", tools)
        self.assertEqual(tools["read"]["provider"], "nvidia-nim")


class TestCreatePerToolGateway(unittest.TestCase):
    def test_factory_creates_gateway(self):
        router = NousPortalRouter([])
        master_key = "d" * 32
        gateway = create_per_tool_gateway(
            router, {"read": {"provider": "nvidia-nim"}}, master_key
        )
        self.assertIsInstance(gateway, PerToolGateway)


if __name__ == "__main__":
    unittest.main()
