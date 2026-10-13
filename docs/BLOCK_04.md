# Block 04: OIDC API boundary and PostgreSQL reservation prototype

## Implemented
- Optional `/v1/oidc/execute` endpoint validates bearer tokens using the existing verifier and binds `sub` to `agent`.
- PostgreSQL reservation primitive uses per-agent transaction advisory locks and a global unique request ID to coordinate replay/rate limits across workers.
- Tests use a fake PostgreSQL connection; **no live PostgreSQL integration test has been run**.

## Critical remaining gaps
- PostgreSQL reservation is not yet wired into Guard execution. Existing SQLite-backed execution is single-process.
- The existing API key endpoint remains enabled by `create_app` and must be disabled/configured for OIDC-only production.
- Approval, audit, kill switch, and execution must share durable distributed transaction semantics; current implementation does not.
- OIDC key rotation/revocation, actual identity provider integration, Vault connectivity, real distributed concurrency tests, threat model, security scans, and deployment testing are outstanding.
- A reservation is not an authorization to execute a tool; always enforce policy and approval independently.

Run tests: `PYTHONPATH=. python -m pytest -q`
