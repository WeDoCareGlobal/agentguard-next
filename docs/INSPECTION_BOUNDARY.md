# Shared inspection boundary — first remediation packet

API-key, scoped bearer and OIDC execution now pass through the same optional
OmniGuard inspection. Inspection is enabled by default. Missing integration,
timeout, malformed response and unverified ALLOW block before Guard admission.
No fallback API key is used; the client requires OMNIGUARD_API_KEY.

The legacy gateway header is not a verifiable request-bound decision. Therefore
ALLOW remains blocked until the signed-decision protocol and its verifier are
implemented. This is intentional containment, not completed gateway integration.
An isolated deployment can explicitly set enable_omniguard=False to use only
local Guard policy. This configuration is not equivalent to OmniGuard protection.

Remaining: signed tenant/principal/payload-bound decisions, expiry and replay
validation, live gateway integration, PostgreSQL tests and full CI/Docker repair.

## Validation 2026-10-16
Baseline main: 1f742fcf68ac0d2092e30533be711cd6c808052a.
Local Python 3.12: 60 tests passed, 24 skipped (PostgreSQL-dependent checks).
Changed API/client/new test file lint passed. Existing identity-only tests now
explicitly disable optional inspection; new tests cover all three execution routes
with timeout, BLOCK and unverified ALLOW. No live gateway was contacted.
Full repository CI, signed-decision interoperability and production are unverified.
