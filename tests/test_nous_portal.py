"""Tests for Nous Portal centralized provider routing (Step 5)."""

import unittest
from agentguard.nous_portal import (
    NousPortalRouter,
    ProviderConfig,
    create_router,
    RouteDecision,
)


class TestProviderConfig(unittest.TestCase):
    def test_config_creation(self):
        cfg = ProviderConfig(
            name="test-provider",
            base_url="https://api.example.com/v1",
            model="example-model",
            api_key_env="EXAMPLE_KEY",
        )
        self.assertEqual(cfg.name, "test-provider")
        self.assertEqual(cfg.model, "example-model")
        self.assertEqual(cfg.api_key_env, "EXAMPLE_KEY")


class TestNousPortalRouter(unittest.TestCase):
    def setUp(self):
        self.providers = [
            ProviderConfig(name="nvidia-nim", base_url="https://nvidia.example.com/v1", model="llama-3.1-nemotron"),
            ProviderConfig(name="xai-grok", base_url="https://xai.example.com/v1", model="grok-2"),
        ]
        self.router = NousPortalRouter(self.providers)

    def test_route_unknown_tool(self):
        decision = self.router.route("nonexistent-tool", {}, "user", "token")
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "no_provider_for_tool")

    def test_single_login(self):
        token1 = self.router.authenticate("emir", "password")
        token2 = self.router.authenticate("emir", "password")
        self.assertEqual(token1, token2)

    def test_token_validation(self):
        token = self.router.authenticate("emir", "password")
        self.assertTrue(self.router.validate_token(token, "emir"))
        self.assertFalse(self.router.validate_token("wrong-token", "emir"))

    def test_per_tool_credential_isolation(self):
        token = self.router.authenticate("emir", "password")
        d1 = self.router.route("nvidia-nim", {}, "emir", token)
        d2 = self.router.route("xai-grok", {}, "emir", token)
        self.assertTrue(d1.allowed)
        self.assertTrue(d2.allowed)
        # Different routing keys for different providers
        self.assertNotEqual(d1.routing_key, d2.routing_key)

    def test_router_created_with_audit_sink(self):
        audit_events = []

        def audit_sink(event):
            audit_events.append(event)

        router = NousPortalRouter(self.providers, audit_hook=audit_sink)
        # Authenticate first to get a valid token
        token = router.authenticate("emir", "password")
        router.route("nvidia-nim", {}, "emir", token)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0]["event"], "route_decision")


class TestCreateRouter(unittest.TestCase):
    def test_create_router_returns_router(self):
        router = create_router()
        self.assertIsInstance(router, NousPortalRouter)

    def test_default_providers(self):
        router = create_router()
        routes = router.get_routes()
        self.assertIn("nvidia-nim", routes)
        self.assertIn("xai-grok", routes)
        self.assertIn("mistral", routes)


if __name__ == "__main__":
    unittest.main()
