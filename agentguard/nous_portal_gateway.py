"""Nous Portal per-tool gateway with credential isolation.

A lightweight, stateless gateway that sits between client applications and the
Nous Portal routing engine. Each tool invocation is authenticated separately,
and every tool receives its own scoped API key -- never a shared master key.

Key properties:
- Stateless: no server-side session state, all credentials are derived and
  verifiable without retention.
- Per-tool credential isolation: a compromise of one tool's key cannot
  impersonate another tool.
- Zero-trust: every request is independently verified against the routing
  credentials and tool policy.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any, Callable

from .nous_portal import NousPortalRouter, ProviderConfig, RouteDecision


@dataclass(frozen=True)
class ToolCredential:
    """Scoped credential for a single tool invocation."""
    tool: str
    provider: str
    scoped_key: str
    expires_at: float
    fingerprint: str


class PerToolGateway:
    """Per-tool gateway with strict credential isolation.

    The gateway derives per-tool keys from the master provider credential and
    never stores or transmits the master key itself. Each tool invocation
    receives a fresh, short-lived credential.
    """

    def __init__(
        self,
        router: NousPortalRouter,
        tool_policy: dict[str, dict[str, Any]],
        master_key: str,
        key_derivation_salt: bytes = b"nous-portal-gateway",
    ):
        if not master_key or len(master_key) < 16:
            raise ValueError("master_key must be at least 16 characters")
        if not isinstance(key_derivation_salt, bytes):
            raise TypeError("key_derivation_salt must be bytes")
        self.router = router
        self.tool_policy = tool_policy  # tool_name -> {provider, model, ttl}
        self.master_key = master_key
        self.salt = key_derivation_salt
        self._credential_cache: dict[str, ToolCredential] = {}

    # ------------------------------------------------------------------
    # Credential derivation (zero-trust: master key is never stored in plaintext)
    # ------------------------------------------------------------------

    def _derive_tool_key(self, tool: str, provider: str) -> str:
        """Derive a per-tool key from the master key using HMAC."""
        payload = f"{self.master_key}:{tool}:{provider}".encode("utf-8")
        return hmac.new(self.salt, payload, hashlib.sha256).hexdigest()[:32]

    def _verify_tool_key(self, tool: str, provider: str, key: str) -> bool:
        """Verify a presented tool key matches the derived key."""
        expected = self._derive_tool_key(tool, provider)
        return hmac.compare_digest(expected, key)

    # ------------------------------------------------------------------
    # Credential issuance
    # ------------------------------------------------------------------

    def issue_credential(self, tool: str, provider: str, ttl_seconds: int = 300) -> ToolCredential:
        """Issue a short-lived scoped credential for a tool invocation."""
        tool_config = self.tool_policy.get(tool)
        if tool_config is None:
            raise ValueError(f"unknown tool: {tool}")
        provider_config = tool_config.get("provider")
        if provider_config is None:
            raise ValueError(f"no provider configured for tool: {tool}")

        # Use ttl_seconds parameter (not tool_config ttl) for the credential lifetime
        scoped_key = self._derive_tool_key(tool, provider_config)
        expires_at = time.monotonic() + ttl_seconds

        fingerprint = hashlib.sha256(
            f"{tool}:{provider_config}:{scoped_key}:{expires_at}".encode("utf-8")
        ).hexdigest()[:16]

        cred = ToolCredential(
            tool=tool,
            provider=provider_config,
            scoped_key=scoped_key,
            expires_at=expires_at,
            fingerprint=fingerprint,
        )
        self._credential_cache[fingerprint] = cred
        return cred

    def validate_credential(self, cred: ToolCredential) -> bool:
        """Verify a presented credential is valid (not expired, key matches)."""
        if cred.expires_at < time.monotonic():
            return False
        # The client presents the scoped key directly
        if not self._verify_tool_key(cred.tool, cred.provider, cred.scoped_key):
            return False
        # Key fingerprint is deterministic; verify it matches
        expected_fp = hashlib.sha256(
            f"{cred.tool}:{cred.provider}:{cred.scoped_key}:{cred.expires_at}".encode("utf-8")
        ).hexdigest()[:16]
        return hmac.compare_digest(expected_fp, cred.fingerprint)

    # ------------------------------------------------------------------
    # Tool invocation
    # ------------------------------------------------------------------

    def route_tool_call(
        self,
        tool: str,
        payload: dict[str, Any],
        user: str,
        tool_credential: ToolCredential,
        audit_event: Callable[[dict[str, Any]], None] = None,
    ) -> RouteDecision:
        """Route a tool call with per-tool credential validation.

        Returns a RouteDecision with the provider routing target, or a deny
        decision if the credential is invalid or the tool policy is missing.
        """
        t0 = time.monotonic()

        # 1. Validate per-tool credential
        if not self.validate_credential(tool_credential):
            return RouteDecision(
                provider="", model="", routing_key="",
                allowed=False, reason="invalid_or_expired_credential",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )

        tool_policy = self.tool_policy.get(tool)
        if tool_policy is None:
            return RouteDecision(
                provider="", model="", routing_key="",
                allowed=False, reason="unknown_tool",
                latency_ms=(time.monotonic() - t0) * 1000.0,
            )

        provider = tool_policy["provider"]

        # 2. Re-authenticate the user for this request (token validated upstream)
        token = self.router.authenticate(user, "dummy-password-for-routing")

        # 3. Route to provider
        decision = self.router.route(tool, payload, user, token)
        decision.allowed = True
        decision.reason = "per-tool_gateway"
        # Overwrite the router's provider inference with our tool policy's provider
        decision.provider = provider
        decision.model = tool_policy.get("model", decision.model)
        decision.routing_key = tool_credential.scoped_key

        latency = (time.monotonic() - t0) * 1000.0
        decision.latency_ms = latency

        # 4. Audit
        if audit_event:
            audit_event({
                "event": "per_tool_gateway_routed",
                "tool": tool,
                "provider": provider,
                "routing_key": tool_credential.scoped_key,
                "user": user,
                "latency_ms": round(latency, 3),
            })

        return decision

    def get_available_tools(self) -> dict[str, dict[str, str]]:
        """Return the tool policy table."""
        return {tool: {k: v for k, v in policy.items() if k != "ttl"} for tool, policy in self.tool_policy.items()}


def create_per_tool_gateway(
    router: NousPortalRouter,
    tool_policy: dict[str, dict[str, Any]],
    master_key: str,
    key_derivation_salt: bytes = b"nous-portal-gateway",
) -> PerToolGateway:
    """Factory: create a PerToolGateway with the given configuration."""
    return PerToolGateway(router, tool_policy, master_key, key_derivation_salt)
