# Hermes: isolated PostgreSQL test environment

Provision a disposable PostgreSQL 16+ database for AgentGuard clean-room stabilization only. Never connect to production databases. Use ephemeral credentials and network-restricted connectivity; do not print secrets.

1. Fetch the full AgentGuard clean-room Phase 1 source artifact from the operator (GitHub branch currently holds documentation only).
2. Launch a disposable PostgreSQL container with health checks, persistent test-only volume, and a dedicated least-privilege user. Do not expose 5432 publicly. Prefer Docker Compose bound to localhost.
3. Supply `AG_TEST_POSTGRES_DSN` securely to the test process (not committed, not logged).
4. Run `python -m pytest -q` and explicitly verify that `tests/test_postgres_live.py` was executed, not skipped.
5. Test parallel admissions for the same request_id, rate-limit atomicity, single-use approvals, shared kill switch, central audit chain verification, database restart, connection failures and rollback. Add tests for any missing scenarios. Use isolated test DB/schema and reset between runs.
6. Capture actual commands, environment versions, test summary, logs with credentials redacted, blockers, and security findings. Never claim a test passed if skipped.
7. Tear down test containers and destroy test secrets after reporting.

Return a PASS/FAIL/SKIP matrix and remediation patch, not deployment to production.
