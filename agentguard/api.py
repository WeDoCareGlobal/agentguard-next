"""Minimal authenticated HTTP boundary; use TLS termination in deployment."""
from __future__ import annotations
import hmac
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Any
from .core import Guard

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

def create_app(guard: Guard, api_key: str, admin_key: str) -> FastAPI:
    if len(api_key) < 32 or len(admin_key) < 32 or hmac.compare_digest(api_key, admin_key):
        raise ValueError("Distinct, strong API and admin keys required")
    app = FastAPI(title="AgentGuard Clean-Room", version="0.1.0")
    def authorize(provided: str | None, expected: str) -> None:
        if not provided or not hmac.compare_digest(provided, expected):
            raise HTTPException(status_code=401, detail="Unauthorized")
    @app.get("/health")
    def health():
        return {"status": "ok"}
    @app.post("/v1/execute")
    def execute(call: Call, x_api_key: str | None = Header(default=None)):
        authorize(x_api_key, api_key)
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


def attach_scoped_execution(app: FastAPI, guard: Guard, authority: 'TokenAuthority') -> None:
    """Add a bearer-authenticated endpoint without changing legacy key endpoints."""
    from .identity import TokenAuthority

    @app.post('/v1/scoped/execute')
    def scoped_execute(call: Call, request: Request):
        auth = request.headers.get('authorization', '')
        if not auth.startswith('Bearer '):
            raise HTTPException(401, 'Unauthorized')
        principal = authority.verify(auth[7:], 'execute', agent=call.agent)
        if principal is None:
            raise HTTPException(403, 'Forbidden')
        return guard.execute(call.agent, call.tool, call.payload, call.request_id, call.approval)


def attach_oidc_execution(app: FastAPI, guard: Guard, verifier: 'OIDCVerifier') -> None:
    """Opt-in OIDC-protected execution route; requires verified execute scope.

    Subject is bound to agent identity; clients cannot impersonate another agent.
    """
    from .oidc import OIDCVerifier

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
