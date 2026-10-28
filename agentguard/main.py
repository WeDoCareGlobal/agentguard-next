"""
AgentGuard entry point — builds the FastAPI app from env configuration.

Used by `agentguard run` (uvicorn loads `agentguard.main:app`) and by the
Docker CMD `agentguard run --policy /app/policy.yaml`.

Environment variables:
  AGENTGUARD_POLICY   Path to policy YAML (required; cli.run sets this)
  AGENTGUARD_API_KEY  API key for /v1/execute (required, >=32 chars)
  AGENTGUARD_ADMIN_KEY Admin key for /v1/admin/* (required, >=32 chars, != api key)
  AGENTGUARD_DB_PATH  SQLite path for local audit/approvals (default: ./agentguard.db)
  AGENTGUARD_MAX_PER_MIN Global per-agent rate limit (default: 60)
  AGENTGUARD_OMNIGUARD Enable OmniGuard inspection (default: true; explicit false only for isolated development)
"""

from __future__ import annotations

import os
from pathlib import Path

from typing import Any, Callable

from fastapi import FastAPI

from .api import attach_optional_console, attach_oidc_execution, attach_scoped_execution, create_app
from .core import Guard, Policy as CorePolicy
from .models import Policy as ModelPolicy
from .policy import load_policy


def _core_policy_from_model(policy: ModelPolicy) -> CorePolicy:
    return CorePolicy(
        allowed=frozenset(policy.allowed_tools),
        denied=frozenset(policy.denied_tools),
        approval_required=frozenset(),
    )


def build_guard(db_path: str | Path, api_key: str | None = None) -> Guard:
    policy_path = os.environ["AGENTGUARD_POLICY"]
    model_policy = load_policy(policy_path)
    core_policy = _core_policy_from_model(model_policy)

    audit_key = os.environ.get("AGENTGUARD_AUDIT_KEY", "").encode()
    if len(audit_key) < 32:
        # Derive a stable key from the API key so the app starts without a
        # separate secret; operators should set AGENTGUARD_AUDIT_KEY for prod.
        import hashlib

        audit_key = hashlib.sha256((api_key or policy_path).encode()).digest()

    max_per_min = int(os.environ.get("AGENTGUARD_MAX_PER_MIN", "60"))

    tools: dict[str, Callable[[Any], Any]] = {}

    return Guard(
        db_path=str(db_path),
        audit_key=audit_key,
        policy=core_policy,
        tools=tools,
        max_per_minute=max_per_min,
    )


def build_app() -> FastAPI:
    api_key = os.environ.get("AGENTGUARD_API_KEY", "")
    admin_key = os.environ.get("AGENTGUARD_ADMIN_KEY", "")
    db_path = os.environ.get("AGENTGUARD_DB_PATH", "./agentguard.db")

    guard = build_guard(db_path, api_key)

    app = create_app(
        guard=guard,
        api_key=api_key,
        admin_key=admin_key,
        enable_omniguard=os.environ.get("AGENTGUARD_OMNIGUARD", "true").strip().lower() != "false",
    )

    # Opt-in local console (private network only)
    attach_optional_console(app, guard, admin_key)

    return app


app = build_app()
