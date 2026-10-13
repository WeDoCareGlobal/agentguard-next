# AgentGuard Next development preview

This branch contains an isolated experimental policy and audit core. It is NOT production-ready.

Implemented: default-deny authorization, deny precedence, approval-required decision and in-memory HMAC audit chain.

NOT implemented: enforcement gateway, authentication, approval execution, durable audit persistence, key management, distributed limits, AgentVault integration, complete private-repository audit, end-to-end tests and deployment.

The eight local pytest tests passed before upload. GitHub CI has not been verified.
Do not deploy as a security boundary. Original repositories remain unchanged.
