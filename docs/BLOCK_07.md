# Block 07 — transactional admission

The new `PostgresCoordinator` performs global halt, replay, per-agent rate limiting,
optional single-use approval consumption, admission reservation, and an admission
record within a single PostgreSQL transaction. The transaction advisory lock
serializes admissions by agent. `Guard` supports this through the optional
`coordinator` argument. The existing `SharedControl` may still be used for issuing
approval tokens and administering the shared halt flag.

## Remaining security and release blockers

- The new coordinator has **not** been exercised against a real PostgreSQL instance;
  tests use a fake coordinator, not a real database.
- The central admission log records accepted requests only. Rejected attempts,
  execution results, and a cryptographically chained centralized audit are not yet
  durable in PostgreSQL.
- Tool execution is not atomic with admission; execution crashes and retries need
  idempotent tools and a reconciliation strategy.
- A global kill switch does not cancel tools already executing.
- Admin APIs, identity boundaries, tenant isolation, migrations, connection pooling,
  retention, backup/restore, and staging security testing remain outstanding.
- The `Guard` uses local SQLite for its per-process audit. The coordinator must not
  be described as a completed centralized audit solution.

No GitHub production branch or public website was modified or deployed.
