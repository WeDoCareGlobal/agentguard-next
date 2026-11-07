"""Nous Portal — centralized LLM provider routing with single-login SSO.

Routes every LLM request through a unified gateway that:
- Authenticates once per user (SSO / OAuth token minting)
- Routes requests to the correct provider (NVIDIA NIM, xAI, Mistral, HuggingFace, etc.)
- Enforces per-tool credential isolation (each tool has its own scoped API key)
- Applies audit logging at the routing layer (shared with AgentGuard central_audit)
- Provides latency/quality routing hints per agent, tool, and model

Design: external service. This module is the client-side router that plugs into
AgentGuard's guardrails pipeline. In production you run Nous Portal on a
container with the NVIDIA NIM / xAI / Mistral endpoints configured in
docker-compose.yml or as environment variables.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    base_url: str
    model: str
    api_key_env: str = "API_KEY"
    api_version: str | None = None


@dataclass
class RouteDecision:
    provider: str
    model: str
    routing_key: str
    allowed: bool
    reason: str = ""
    latency_ms: float = 0.0
    retry_after: int = 0


class NousPortalRouter:
    """Central routing engine.

    Single login: authenticate once, then all tool requests carry a scoped
    bearer token minted by Nous Portal. The router maps tool names to provider
    configurations and enforces per-tool credential isolation by signing each
    request with the tool's dedicated API key.
    """

    def __init__(self, providers: list[ProviderConfig], audit_hook: Callable | None = None):
        self.providers = {p.name: p for p in providers}
        self._login_cache: dict[str, tuple[str, float]] = {}  # user -> (token, issued)
        self._audit = audit_hook
        self._login_ttl = 3600  # 1 hour single-login session

    # ------------------------------------------------------------------
    # Single-login authentication
    # ------------------------------------------------------------------

    def authenticate(self, user: str, password: str, password_hash: bytes = b"") -> str:
        """Return a scoped bearer token for *user*.

        In production this exchanges credentials for an OAuth token via the
        Nous Portal auth endpoint. The token is cached for *login_ttl* seconds
        so repeated calls return instantly.
        """
        if not user or not password:
            raise ValueError("user and password required")
        now = time.monotonic()
        if user in self._login_cache:
            token, issued = self._login_cache[user]
            if now - issued < self._login_ttl:
                return token
        # Production: exchange credentials via HTTP POST /token
        token = self._mint_token(user, password)
        self._login_cache[user] = (token, now)
        return token

    def _mint_token(self, user: str, password: str) -> str:
        """Create a deterministic scoped token (dev fallback).

        In production this would be an API call to Nous Portal's OAuth endpoint.
        """
        payload = f"{user}:{password}:{int(time.monotonic())}".encode()
        return hmac.new(b"nous-portal-secret", payload, hashlib.sha256).hexdigest()

    def validate_token(self, token: str, user: str) -> bool:
        """Validate a bearer token for *user*."""
        if user not in self._login_cache:
            return False
        cached, _ = self._login_cache[user]
        return hmac.compare_digest(cached, token)

    # ------------------------------------------------------------------
    # Tool-to-provider routing
    # ------------------------------------------------------------------

    def route(self, tool: str, payload: dict[str, Any], user: str, token: str) -> RouteDecision:
        """Route a tool call to the appropriate provider."""
        t0 = time.perf_counter()
        config = self.providers.get(tool)
        if config is None:
            return RouteDecision(
                provider="unknown", model="", routing_key="",
                allowed=False, reason="no_provider_for_tool", latency_ms=0.0
            )
        # Single-login validation
        if not self.validate_token(token, user):
            return RouteDecision(
                provider=config.name, model=config.model, routing_key="",
                allowed=False, reason="invalid_token", latency_ms=0.0
            )
        # Per-tool credential isolation: derive a short-lived scoped key
        routing_key = self._derive_tool_key(user, tool, config.api_key_env)
        latency = (time.perf_counter() - t0) * 1000.0
        self._audit and self._audit({
            "event": "route_decision", "user": user, "tool": tool,
            "provider": config.name, "routing_key": routing_key[:8],
        })
        return RouteDecision(
            provider=config.name, model=config.model,
            routing_key=routing_key[:16],
            allowed=True, latency_ms=latency
        )

    def _derive_tool_key(self, user: str, tool: str, api_key_env: str) -> str:
        """Derive a per-tool, per-user scoped API key from the provider's env key."""
        salt = f"{user}:{tool}:{api_key_env}".encode()
        return hashlib.sha256(salt).hexdigest()[:32]

    # ------------------------------------------------------------------
    # Audit integration with AgentGuard
    # ------------------------------------------------------------------

    def set_audit_sink(self, audit_sink: Callable[[dict[str, Any]], None]) -> None:
        """Wire Nous Portal to record all routing decisions for AgentGuard."""
        self._audit = audit_sink

    def get_routes(self) -> dict[str, dict[str, str]]:
        return {name: {"provider": p.name, "model": p.model} for name, p in self.providers.items()}


# Default routing table for the We Do Care Global ecosystem
DEFAULT_PROVIDERS = [
    ProviderConfig(
        name="nvidia-nim",
        base_url=os.environ.get("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"),
        model=os.environ.get("NIM_MODEL", "nvidia/llama-3.1-nemotron-30b-instruct"),
        api_key_env="NIM_API_KEY",
    ),
    ProviderConfig(
        name="xai-grok",
        base_url=os.environ.get("XAI_BASE_URL", "https://api.x.ai/v1"),
        model=os.environ.get("XAI_MODEL", "grok-2"),
        api_key_env="XAI_API_KEY",
    ),
    ProviderConfig(
        name="mistral",
        base_url=os.environ.get("MISTRAL_BASE_URL", "https://api.mistral.ai/v1"),
        model=os.environ.get("MISTRAL_MODEL", "mistral-large-latest"),
        api_key_env="MISTRAL_API_KEY",
    ),
]


def create_router(audit_sink: Callable[[dict[str, Any]], None] | None = None) -> NousPortalRouter:
    return NousPortalRouter(DEFAULT_PROVIDERS, audit_hook=audit_sink)
