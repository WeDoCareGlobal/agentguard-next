# AgentGuard — Clean-Room Rebuild (0.1.0)

Entirely new implementation. **No code copied from legacy AgentGuard repositories or earlier RC/M1 packages.**

## Capabilities
- Default-deny policy, explicit tool registry, deny precedence
- Bound, single-use, expiring approval tokens (admin-only issuance)
- Replay protection via durable request IDs, per-agent rate limits
- Kill switch, HMAC-chained SQLite audit, audit verification
- HTTP API with distinct user/admin keys; injected tool functions

## Local test
```bash
python -m pip install -e '.[test]'
pytest -q
```

## Integrate
Create a Guard with your own explicitly approved callable tools, then call `create_app(guard, api_key, admin_key)` and serve using an ASGI server. No demo tool automatically executes external commands.

## Limitations / NOT PRODUCTION READY
Single-process SQLite reference implementation; no cross-process atomic execution, crash-safe job completion, distributed quotas, enterprise identity, secret vault, independent audit anchoring, key rotation, full approval actor identity, proxy protocol, dashboard, or operational runbooks. HTTP API keys are static and must be managed externally. Audit chain does not detect tail truncation without external checkpoints. Never expose without TLS, authorization gateway and further hardening. The grant endpoint is a privileged operator action, not a multi-party approval workflow.


## Version 0.4.0 development block
See `docs/BLOCK_04.md` for OIDC API binding and PostgreSQL reservation prototype. Not production ready.


## Block 05

Optional distributed reservation wired into Guard; see `docs/BLOCK_05.md`. **Not production-ready.**


## Version 0.6.0 development update

Added optional PostgreSQL-backed shared halt and one-time approvals (`agentguard.shared_control`). See `docs/BLOCK_06.md` for limitations and release blockers.

## Development 0.7.0 — PostgreSQL transactional admission

Added `agentguard.coordination.PostgresCoordinator`, optional `Guard` integration,
and unit tests for approval preservation, replay, kill switch and outages. See
`docs/BLOCK_07.md` for deployment blockers. This is **not** a production release.

## 0.8.0 development block

Introduces an optional PostgreSQL centralized HMAC audit adapter. See `docs/BLOCK_08.md` for integration requirements and production blockers. No live PostgreSQL verification or deployment was performed.

## 0.9.0 development block

Optional central audit integration with pre-execution fail-closed behavior. See `docs/BLOCK_09.md` for known limitations. This is **not** a production release.


## Blocks 09–10 development update
Opt-in real PostgreSQL integration test harness and read-only audit-health Command Center. See `docs/BLOCK_10.md` for validation and blockers.
