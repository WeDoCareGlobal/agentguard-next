# Block 03: external identity and secret access

## Implemented
- Pinned-JWKS, RS256 JWT verification with issuer, audience, scope, signature and lifetime checks. The verifier **does not fetch JWKS**, issue tokens or implement OIDC discovery. Key rotation, revocation and identity-provider configuration remain deployment tasks.
- Vault KV v2 read-only secret provider. HTTPS-only, no redirects, no environment proxy, short timeout, explicit secret-name validation. The adapter requires a live Vault instance and authorized token; **not connected or live-tested**.
- Unit tests include signature tampering, expiration, scope/audience mismatch and Vault fail-closed errors.

## Not yet complete
- Integrate OIDCVerifier into API dependency injection with separate RBAC for admin and operator endpoints; remove static-key production paths.
- Integrate VaultKV2Provider into approved tool registration, short-lived workload identity and Vault auth renewal.
- PostgreSQL atomic request/approval reservations and distributed quotas. SQLite is still single-process reference only.
- Real web Command Center, observability, live integration and penetration tests.

## Security constraints
Never place Vault tokens or secret values in Git, logs or UI. Configure TLS and JWKS through a trusted deployment pipeline. Do not treat this as a production-ready release.
