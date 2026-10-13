# Blocks 09 and 10 — verification and Command Center

## Block 09: real PostgreSQL integration harness
`tests/test_postgres_live.py` exercises four concurrent admission requests against a **disposable** PostgreSQL database and validates audit append/verify. Run `AG_TEST_POSTGRES_DSN=postgresql://... pytest -q tests/test_postgres_live.py` only on an isolated test DB. Without DSN, the test is skipped. This is not evidence of live verification.

## Block 10: administrative observability
The read-only Command Center now exposes `/v1/admin/status` with local and optional central audit health, escaped HTML events, CSP, no-store, and admin-key access. The console remains an early administrative UI, not a production enterprise dashboard. Never expose it publicly with a static shared key.

## Outstanding release blockers
- Live PostgreSQL tests not executed until disposable database available.
- No fully atomic admission + pre-execution audit transaction.
- Tool side effects cannot be rolled back; add idempotency contracts and recovery/reconciliation.
- Replace static administrator keys with production OIDC/RBAC; central JWKS rotation and tenant isolation.
- Independent penetration/security review, backups/restore, external audit anchoring, load tests, staging deployment, and user acceptance.
- No GitHub pushes, merges, production deployment or public republish performed.
