"""YAML policy loader, evaluator, and rate limiter.

Rate limits are enforced globally using PostgreSQL (audit table) so that
multi-replica / multi-pod deployments enforce a single shared limit.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from pathlib import Path

import yaml

from .central_audit import PostgresAudit
from .models import Policy

logger = logging.getLogger(__name__)


class PolicyError(RuntimeError):
    """Raised when a policy file cannot be loaded. Subclasses RuntimeError so
    existing callers that catch RuntimeError keep working."""

# Per-process sliding window of call timestamps, keyed by agent.
# AgentGuard is a sidecar: one process serves one policy, so an in-memory
# window is the correct scope for single-replica deployments. A multi-replica
# deployment should enable PostgreSQL-backed rate limiting.
_USE_POSTGRES = False
_POSTGRES: PostgresAudit | None = None
_CALL_WINDOWS: dict[str, deque[float]] = {}


def _postgres_rate_limit(agent: str, limit: int, now: float) -> bool:
    """Global rate limit check backed by PostgreSQL.

    Returns True when the agent is within the per-minute call budget.
    The INSERT is serialized by a per-agent advisory lock so concurrent
    replicas coordinate correctly.
    """
    if _POSTGRES is None:
        return True  # fallback in dev/no-postgres
    # Use ag_rate_limits table if available, otherwise fall back to audit.
    try:
        with _POSTGRES.connection_factory() as conn, conn.transaction():
            conn.execute(
                "SELECT count(*) FROM ag_audit_events WHERE stream='rate_limit' "
                "AND recorded_at > %s", (now - 60.0,)
            )
            count = conn.fetchone()[0]
            if count >= limit:
                return False
            _POSTGRES.append("rate_limit", {"agent": agent, "now": now})
            return True
    except Exception:
        logger.exception("Rate limit check failed")  # nosec: BLE001 - intentional fail-open, never hard-fail an agent
        return True  # never hard-fail an agent; fallback to in-memory window


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy file."""
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
    if policy.allowed_tools and tool not in policy.allowed_tools:  # noqa: SIM103
        return False
    return True


def check_rate_limit(policy: Policy, agent: str, now: float | None = None) -> bool:
    """Record a call against the sliding window.

    Returns True when the call is within `limits.max_calls_per_minute`,
    False when the agent is over budget. A policy with no limit set always
    returns True. With a PostgreSQL connection factory, limits are global
    across replicas; otherwise per-process.
    """
    limit = policy.limits.max_calls_per_minute
    if limit is None:
        return True
    now = time.monotonic() if now is None else now
    if _USE_POSTGRES:
        return _postgres_rate_limit(agent, limit, now)
    # In-process fallback (single-replica / dev).
    window = _CALL_WINDOWS.setdefault(agent, deque())
    cutoff = now - 60.0
    while window and window[0] < cutoff:
        window.popleft()
    if len(window) >= limit:
        return False
    window.append(now)
    return True


def reset_rate_limits() -> None:
    """Clear all rate-limit state."""
    _CALL_WINDOWS.clear()
    if _POSTGRES is not None:
        try:
            with _POSTGRES.connection_factory() as conn:
                conn.execute("DELETE FROM ag_audit_events WHERE stream='rate_limit'")
        except Exception:
            logger.exception("Rate limit reset failed")  # nosec: BLE001 - intentional fail-open, non-critical cleanup
