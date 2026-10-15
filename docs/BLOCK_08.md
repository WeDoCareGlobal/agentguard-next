# Block 08 — Central audit implementation

Added `agentguard.central_audit.PostgresAudit`: PostgreSQL-backed per-stream append-only event log, transactional advisory lock, HMAC-SHA256 hash chaining, sequence verification and mutation/gap detection. This module is **not yet wired to all Guard/API execution paths**; application code must call it and treat write failures as blocking for security-critical actions.

## Verification and release blockers

- Local tests use a fake PostgreSQL connection. **No live PostgreSQL server was used.**
- A compromised privileged DB administrator can truncate the log tail without detection. Periodically publish signed head checkpoints to an independent immutable store and alert on missing checkpoints.
- Use a dedicated least-privilege database role: INSERT/SELECT only for runtime, no UPDATE/DELETE/TRUNCATE, plus separate migration role. DDL is only for setup.
- HMAC key must be sourced from KMS/Vault, never committed; define key rotation and retention before production.
- Centralized audit must be integrated with all admission/approval/denial paths and tested under real concurrent transactions and failure injection.
- Deployment, end-to-end test, monitoring, OIDC identity and Vault connectivity are not certified.
