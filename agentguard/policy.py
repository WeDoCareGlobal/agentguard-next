"""YAML policy loader, evaluator, and rate limiter."""
from __future__ import annotations

import time
from collections import deque
from pathlib import Path

import yaml

from .models import Policy

# Per-process sliding window of call timestamps, keyed by agent.
# AgentGuard is a sidecar: one process serves one policy, so an in-memory
# window is the correct scope. A multi-replica deployment should move this
# to the audit table (or Redis) so limits are global, not per-pod.
_CALL_WINDOWS: dict[str, deque[float]] = {}


class PolicyError(RuntimeError):
    """Raised when a policy file cannot be loaded. Subclasses RuntimeError so
    existing callers that catch RuntimeError keep working."""


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy file.

    Raises PolicyError (a RuntimeError) with an actionable message instead of
    letting a bare FileNotFoundError/KeyError escape at import time.
    """
    p = Path(path)
    if not p.exists():
        raise PolicyError(
            f"policy file not found: {p}\n"
            f"  Create one with:  agentguard init --agent <name>\n"
            f"  Or point at an existing file:  agentguard run --policy <path>\n"
            f"  A committed example lives at policy.example.yaml."
        )
    try:
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"{p} is not valid YAML: {exc}") from exc
    try:
        return Policy(**data)
    except Exception as exc:
        raise PolicyError(f"{p} does not match the policy schema: {exc}") from exc


def is_allowed(policy: Policy, tool: str) -> bool:
    if tool in policy.denied_tools:
        return False
    if policy.allowed_tools and tool not in policy.allowed_tools:
        return False
    return True


def check_rate_limit(policy: Policy, agent: str, now: float | None = None) -> bool:
    """Record a call against the sliding window.

    Returns True when the call is within `limits.max_calls_per_minute`,
    False when the agent is over budget. A policy with no limit set always
    returns True.
    """
    limit = policy.limits.max_calls_per_minute
    if limit is None:
        return True
    now = time.monotonic() if now is None else now
    window = _CALL_WINDOWS.setdefault(agent, deque())
    cutoff = now - 60.0
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= limit:
        return False
    window.append(now)
    return True


def reset_rate_limits() -> None:
    """Clear all sliding windows (used by tests and by the /audit reset path)."""
    _CALL_WINDOWS.clear()
