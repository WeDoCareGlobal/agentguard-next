# Block 05 — Distributed reservation integration

The optional `reservation_store` argument on `Guard` now wires cross-worker replay/rate-limit reservation into the actual execution path. Reservation failures fail closed. Tests cover two Guard instances and simulated coordination outage.

**Important:** This is not a fully distributed production guard. Approval tokens, kill switch, and audit are still local SQLite, and the PostgreSQL path has not been tested against a live database. Cross-process SQLite writes require explicit transaction handling and concurrency tests. A successful reservation is consumed even if subsequent execution fails. Tool side effects cannot be rolled back; retries require application-level idempotency. This release is not ready for production.
