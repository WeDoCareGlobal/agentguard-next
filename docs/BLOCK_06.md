# Block 06 — Shared control primitives

New `SharedControl` PostgreSQL adapter supports shared kill switch and one-time approval consumption using atomic `UPDATE ... RETURNING`. `Guard` optionally delegates approvals and halt checks to it. On shared-control lookup errors, execution fails closed.

## Security and deployment limitations
- No live PostgreSQL integration test in this environment. In-memory fake tests only.
- The local SQLite audit and request store remain per instance; audit is not centralized.
- Approval tokens may be consumed before a downstream rate-limit/reservation denial. This is safe (no unauthorized execution) but impacts usability; needs a unified transaction or two-phase reservation.
- No remote administrative authentication, multi-tenant isolation, policy distribution, or live Vault connection demonstrated.
- Configure a fresh PostgreSQL connection per operation, TLS, least-privilege database credentials and secret rotation before staging.
- No deployment or publish has been performed.
