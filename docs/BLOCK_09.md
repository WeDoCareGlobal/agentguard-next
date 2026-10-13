# Block 09: central audit enforcement integration

`Guard(central_audit=PostgresAudit(...))` now writes the decision before executing an allowed tool, and a completion/failure record afterwards. If the decision audit cannot be committed, execution is denied. A failure to write the completion record after execution returns ERROR but **cannot undo the tool side effect**. Callers must not blindly retry; request IDs are reserved.

## Not yet verified

- Real PostgreSQL concurrency, crash recovery, TLS and credentials.
- Distributed admission and central audit are **not** in a single atomic transaction. A decision can be admitted but fail audit, consuming an approval or rate-limit slot. This is safe against unauthorized execution but can affect availability.
- Central audit verification cannot detect tail deletion without an external anchored checkpoint.
- Some administrative and invalid-request paths still use local audit only.
- Full Command Center, end-to-end staging, production security review and republish are pending.
