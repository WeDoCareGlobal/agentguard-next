from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class Limits(BaseModel):
    """Rate limits enforced per policy. These used to live as a bare dict in
    Policy.limits: `agentguard init` wrote them into policy.yaml, but no code
    ever read them."""

    max_calls_per_minute: int | None = None
    max_usd_per_day: float | None = None
    max_tokens_per_call: int | None = None


class Policy(BaseModel):
    agent: str
    allowed_tools: list[str] = Field(default_factory=list)
    denied_tools: list[str] = Field(default_factory=list)
    limits: Limits = Field(default_factory=Limits)


class AuditEntry(BaseModel):
    id: int | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    agent: str
    tool: str
    input: str
    output: str
    decision: str  # ALLOWED, DENIED, APPROVAL_REQUIRED, RATE_LIMITED
    approved_by: str | None = None
    # Tamper-evidence: each row commits to the one before it, so editing or
    # deleting any history invalidates every hash after it.
    prev_hash: str = ""
    entry_hash: str = ""
