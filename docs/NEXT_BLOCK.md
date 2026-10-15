# Next block: implemented and outstanding

Implemented: scoped HMAC tokens (standalone primitive), environment secret-provider interface, opt-in read-only HTML audit console. This is newly authored code and not copied from previous repositories.

**Not implemented:** OIDC/JWKS, MFA, token revocation, full RBAC, actual AgentVault connector, secret rotation, PostgreSQL/Redis coordination, HA-safe approval redemption, browser session management, production-grade Command Center. The existing API continues to use static API keys; scoped tokens are not yet wired into API authorization. SQLite and in-process locks do not provide distributed correctness. Do not deploy publicly.

Console uses an administrator header; browsers cannot conveniently supply it by navigating to a URL. Use an authenticated reverse proxy or API client in a private environment. Do not embed credentials in URLs.
