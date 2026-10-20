"""OmniGuard client for FoundationCentar-Next integration."""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx


class OmniGuardDecision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


@dataclass
class OmniGuardResult:
    decision: OmniGuardDecision
    confidence: float
    signature: str
    latency_ms: float
    tier_latencies: dict[str, float]
    blocked_reason: str | None = None


class OmniGuardClient:
    """Client for OmniGuard gateway (http://localhost:8000/v1)."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000/v1",
        api_key: str | None = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        # Read API key from env; never embed default secrets in code.
        self.api_key = api_key or os.environ.get("OMNIGUARD_API_KEY")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=httpx.Headers({"X-API-Key": self.api_key or ""}),
                timeout=self.timeout,
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def inspect(
        self,
        messages: list[dict[str, Any]],
        model: str = "omniguard-2.0",
        metadata: dict[str, Any] | None = None,
    ) -> OmniGuardResult:
        """Send messages to OmniGuard for inspection."""
        client = await self._get_client()
        payload = {
            "model": model,
            "messages": messages,
            "metadata": metadata or {},
        }
        try:
            resp = await client.post("chat/completions", json=payload)
            if resp.status_code == 403:
                try:
                    error = resp.json()
                    reason = error.get("block_reason") or error.get("error") or error.get("detail")
                except (ValueError, AttributeError):
                    reason = "OmniGuard blocked request"
                return OmniGuardResult(
                    decision=OmniGuardDecision.BLOCK,
                    confidence=1.0,
                    signature=resp.headers.get("X-Governance-Signature", ""),
                    latency_ms=0.0,
                    tier_latencies={},
                    blocked_reason=str(reason),
                )
            resp.raise_for_status()
            if resp.status_code != 200 or resp.headers.get("X-Governance-Decision") != "ALLOW":
                raise ValueError("OmniGuard did not explicitly allow execution")
            decision_header = resp.headers.get("X-Governance-Decision", "BLOCK")
            decision = OmniGuardDecision(decision_header)
            return OmniGuardResult(
                decision=decision,
                confidence=float(resp.headers.get("X-Governance-Confidence", "0.0")),
                signature=resp.headers.get("X-Governance-Signature", ""),
                latency_ms=float(resp.headers.get("X-Inspection-Latency-Ms", "0.0")),
                tier_latencies={
                    "tier0": float(resp.headers.get("X-Tier0-Latency-Ms", "0.0")),
                    "tier1": float(resp.headers.get("X-Tier1-Latency-Ms", "0.0")),
                    "tier2": float(resp.headers.get("X-Tier2-Latency-Ms", "0.0")),
                    "tier3": float(resp.headers.get("X-Tier3-Latency-Ms", "0.0")),
                },
                blocked_reason=resp.json().get("detail") if decision == OmniGuardDecision.BLOCK else None,
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                return OmniGuardResult(
                    decision=OmniGuardDecision.BLOCK,
                    confidence=1.0,
                    signature="",
                    latency_ms=0.0,
                    tier_latencies={},
                    blocked_reason=e.response.text,
                )
            raise

    async def health_check(self) -> bool:
        """Check if OmniGuard gateway is healthy."""
        try:
            client = await self._get_client()
            resp = await client.get(f"{self.base_url.removesuffix('/v1')}/healthz")
            return resp.status_code == 200 and resp.json().get("status") == "healthy"
        except Exception:
            return False


# Singleton instance
_omniguard_client: OmniGuardClient | None = None
_omniguard_lock = threading.Lock()


def get_omniguard_client() -> OmniGuardClient:
    """Thread-safe lazy singleton for the OmniGuard client."""
    global _omniguard_client
    if _omniguard_client is None:
        with _omniguard_lock:
            if _omniguard_client is None:
                _omniguard_client = OmniGuardClient()
    return _omniguard_client


async def close_omniguard_client() -> None:
    global _omniguard_client
    if _omniguard_client:
        await _omniguard_client.close()
        _omniguard_client = None