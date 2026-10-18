"""Minimal authenticated HTTP boundary with OmniGuard integration; use TLS termination in deployment."""
from __future__ import annotations

import hmac
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .core import Guard
from .oidc import OIDCVerifier

# OmniGuard integration
try:
    from .omniguard_client import OmniGuardDecision, get_omniguard_client
    OMNIGUARD_AVAILABLE = True
except ImportError:
    OMNIGUARD_AVAILABLE = False
    OmniGuardDecision = None

class Call(BaseModel):
    agent: str = Field(min_length=1, max_length=128)
    tool: str = Field(min_length=1, max_length=128)
    request_id: str = Field(min_length=1, max_length=200)
    payload: Any
    approval: str | None = None

class Approval(BaseModel):
    agent: str
    tool: str
    payload: Any
    ttl: int = Field(default=120, ge=1, le=3600)

class Halt(BaseModel):
    enabled: bool

async def _omniguard_inspect(agent: str, tool: str, payload: Any) -> str | None:
    """Inspect tool call via OmniGuard. Returns block reason if blocked, None if allowed."""
    if not OMNIGUARD_AVAILABLE:
        return None
    try:
        omniguard = get_omniguard_client()
        messages = [
            {"role": "system", "content": "AgentGuard tool call inspection"},
            {"role": "user", "content": f"Agent: {agent}, Tool: {tool}, Payload: {payload}"},
        ]
        result = await omniguard.inspect(messages)
        if result.decision == OmniGuardDecision.BLOCK:
            return result.blocked_reason or "OmniGuard policy violation"
    except Exception:
        # Fail-open for OmniGuard errors (don't block legitimate calls if OmniGuard is down)
        pass
    return None

def create_app(guard: Guard, api_key: str, admin_key: str, enable_omniguard: bool = True) -> FastAPI:
    if len(api_key) < 32 or len(admin_key) < 32 or hmac.compare_digest(api_key, admin_key):
        raise ValueError("Distinct, strong API and admin keys required")
    app = FastAPI(title="AgentGuard Clean-Room", version="0.1.0")
    def authorize(provided: str | None, expected: str) -> None:
        if not provided or not hmac.compare_digest(provided, expected):
            raise HTTPException(status_code=401, detail="Unauthorized")
    @app.get("/health")
    def health():
        return {"status": "ok", "omniguard_enabled": enable_omniguard and OMNIGUARD_AVAILABLE}
    @app.post("/v1/execute")
    async def execute(call: Call, x_api_key: str | None = Header(default=None)):
        authorize(x_api_key, api_key)
        # OmniGuard inspection
        if enable_omniguard and OMNIGUARD_AVAILABLE:
            block_reason = await _omniguard_inspect(call.agent, call.tool, call.payload)
            if block_reason:
                raise HTTPException(status_code=403, detail=f"OmniGuard blocked: {block_reason}")
        return guard.execute(call.agent, call.tool, call.payload, call.request_id, call.approval)
    @app.post("/v1/admin/approvals")
    def grant(req: Approval, x_admin_key: str | None = Header(default=None)):
        authorize(x_admin_key, admin_key)
        try:
            return {"token": guard.grant(req.agent, req.tool, req.payload, req.ttl)}
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid approval request")
    @app.post("/v1/admin/halt")
    def halt(req: Halt, x_admin_key: str | None = Header(default=None)):
        authorize(x_admin_key, admin_key)
        guard.set_kill_switch(req.enabled)
        return {"enabled": req.enabled}
    @app.get("/v1/admin/audit/verify")
    def verify(x_admin_key: str | None = Header(default=None)):
        authorize(x_admin_key, admin_key)
        return {"valid": guard.verify_audit()}
    return app


def attach_optional_console(app: FastAPI, guard: Guard, admin_key: str) -> None:
    """Opt-in local console; require a private network and secure proxy."""
    from .console import console_router
    app.include_router(console_router(guard, admin_key))


def attach_scoped_execution(app: FastAPI, guard: Guard, authority: TokenAuthority) -> None:
    """Add a bearer-authenticated endpoint without changing legacy key endpoints."""

    @app.post('/v1/scoped/execute')
    def scoped_execute(call: Call, request: Request):
        auth = request.headers.get('authorization', '')
        if not auth.startswith('Bearer '):
            raise HTTPException(401, 'Unauthorized')
        principal = authority.verify(auth[7:], 'execute', agent=call.agent)
        if principal is None:
            raise HTTPException(403, 'Forbidden')
        return guard.execute(call.agent, call.tool, call.payload, call.request_id, call.approval)


def attach_oidc_execution(app: FastAPI, guard: Guard, verifier: OIDCVerifier) -> None:
    """Opt-in OIDC-protected execution route; requires verified execute scope.

    Subject is bound to agent identity; clients cannot impersonate another agent.
    """

    @app.post('/v1/oidc/execute')
    def oidc_execute(call: Call, request: Request):
        authorization = request.headers.get('authorization', '')
        if not authorization.startswith('Bearer ') or len(authorization) > 16400:
            raise HTTPException(status_code=401, detail='Unauthorized')
        principal = verifier.verify(authorization[7:], 'execute')
        if principal is None:
            raise HTTPException(status_code=401, detail='Unauthorized')
        if principal.subject != call.agent:
            raise HTTPException(status_code=403, detail='Agent mismatch')
        return guard.execute(call.agent, call.tool, call.payload, call.request_id, call.approval)
