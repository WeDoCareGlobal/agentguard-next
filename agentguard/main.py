"""FastAPI service – the agentguard sidecar."""
from __future__ import annotations

import os

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .audit import add_audit, get_engine, init_db, list_audit, verify_chain
from .models import AuditEntry, Policy
from .policy import PolicyError, check_rate_limit, is_allowed, load_policy

# Prometheus metrics
REQUEST_COUNT = Counter("http_requests_total", "Total HTTP requests", ["method", "endpoint", "status"])
REQUEST_LATENCY = Histogram("http_request_duration_seconds", "HTTP request latency", ["method", "endpoint"])
TOOL_CALLS = Counter("tool_calls_total", "Total tool calls", ["tool", "decision"])
TOOL_CALL_DURATION = Histogram("tool_call_duration_seconds", "Tool call duration", ["tool"])

app = FastAPI(title="agentguard", version="0.2.0")

# Trusted host (adjust for production)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])


# Dependency: DB session
def get_db():
    engine = get_engine()
    with Session(engine, future=True) as session:
        yield session


# Load policy at startup (can be overridden via env)
POLICY_PATH = os.getenv("AGENTGUARD_POLICY", "policy.yaml")
try:
    POLICY: Policy = load_policy(POLICY_PATH)
except PolicyError as exc:
    # PolicyError already carries an actionable message; re-raise it as-is
    # instead of burying it in a bare RuntimeError.
    raise RuntimeError(str(exc)) from exc

# Ensure DB tables exist
init_db(get_engine())


class ToolCallRequest(BaseModel):
    agent: str
    tool: str
    input: str


class ToolCallResponse(BaseModel):
    decision: str  # ALLOWED, DENIED, APPROVAL_REQUIRED, RATE_LIMITED
    audit_id: int
    message: str | None = None


@app.post("/toolcall", response_model=ToolCallResponse)
def toolcall(req: ToolCallRequest, session: Session = Depends(get_db)):
    # Simple agent name match – extend as needed
    if req.agent != POLICY.agent:
        raise HTTPException(status_code=403, detail="Agent mismatch")

    # Rate limit first: an over-budget agent is refused before any policy
    # evaluation, and the refusal is audited like any other decision.
    if not check_rate_limit(POLICY, req.agent):
        entry = add_audit(
            session,
            AuditEntry(
                agent=req.agent,
                tool=req.tool,
                input=req.input,
                output="",
                decision="RATE_LIMITED",
            ),
        )
        return ToolCallResponse(
            decision="RATE_LIMITED",
            audit_id=entry.id,
            message=(
                "Rate limit exceeded: "
                f"{POLICY.limits.max_calls_per_minute} calls/minute"
            ),
        )

    allowed = is_allowed(POLICY, req.tool)
    decision = "ALLOWED" if allowed else "DENIED"

    # For demo, treat DENIED as requiring approval (you can change logic)
    if not allowed:
        decision = "APPROVAL_REQUIRED"

    audit_entry = add_audit(
        session,
        AuditEntry(
            agent=req.agent,
            tool=req.tool,
            input=req.input,
            output="",  # output filled later by caller
            decision=decision,
        ),
    )

    TOOL_CALLS.labels(tool=req.tool, decision=decision).inc()

    return ToolCallResponse(
        decision=decision,
        audit_id=audit_entry.id,
        message=None if allowed else "Tool denied – awaiting approval",
    )


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# Optional: endpoint to fetch recent audit
@app.get("/audit", response_model=list[AuditEntry])
def get_audit(limit: int = 50, session: Session = Depends(get_db)):
    return list_audit(session, limit=limit)


@app.get("/audit/verify")
def get_audit_verify(session: Session = Depends(get_db)):
    """Recompute the audit hash chain.

    ok=false with a first_broken id means the log was edited or truncated
    after that row: every later entry's prev_hash no longer lines up.
    """
    ok, broken = verify_chain(session)
    return {"ok": ok, "first_broken_id": broken, "length": len(list_audit(session, limit=10**9))}


if __name__ == "__main__":
    uvicorn.run("agentguard.main:app", host="0.0.0.0", port=8000, reload=False)
