# Pre-Release Consolidation Baseline — agentguard-next

## Issue Reference
- Issue #2: "Pre-release: original-code consolidation and 10-step completion plan" (open)
- Acceptance: All required tests on exact candidate SHA; no mocked success, undocumented skipped integrations, exposed credentials, missing attribution, or unproven product claims. Preserve donor repositories; adapt selected modules on development branches. No public release or production deployment in this planning task. OmniGuard remains excluded.

## Baseline SHAs (from issue)
| Reference | SHA | Description |
|-----------|-----|-------------|
| Audit branch | 02bed57 | fix: fail closed when local audit integrity is compromised |
| Stabilization branch | f3ee682 | ci: execute AgentGuard unit test suite on development branch |
| Current HEAD | 25dfdf5 | Merge pull request #13 from WeDoCareGlobal/fix/ci-release-gates |

## Delta
- Commits ahead of audit branch (02bed57): 120
- Commits ahead of stabilization (f3ee682): 118

## Step 1 Status: IN PROGRESS
**Task:** Usporediti stabilization f3ee682 i audit 02bed57; objediniti popravke uz očuvanje CI workflowa i test_audit_sequence.py.
(Diff: stabilization→audit removes python-checks.yml CI (15 lines), modifies agentguard/core.py (14 lines), adds docs/AUDIT_2026_10_14.md (11 lines), adds tests/test_audit_enforcement.py (25 lines), removes tests/test_audit_sequence.py (22 lines).)

**Resolution plan:**
1. Preserve `.github/workflows/python-checks.yml` from stabilization (f3ee682)
2. Preserve `tests/test_audit_sequence.py` from stabilization (f3ee682)
3. Apply fail-closed audit fix from `agentguard/core.py` in audit (02bed57)
4. Add `docs/AUDIT_2026_10_14.md` and `tests/test_audit_enforcement.py` from audit (02bed57)
5. Verify CI passes on unified branch

## Source Selection (from issue)
| Source | Decision | Reason |
|--------|----------|--------|
| Original agentguard/agentguard/policy.py | Selectively adapt | Selective rules + tests |
| agentguard-next core.py | Keep | Core module |
| agentguard-next audit/ | Keep | Audit module |
| agentguard-next identity/Postgres | Keep | Postgres moduli |
| AgentGuard-UI-Component | Candidate for UI | Not proven security functionality |

## Steps 2–10
Documented in issue #2 body. Not started.

## Verification
- [ ] Baseline documented (this file)
- [ ] Step 1 unified (CI + test_audit_sequence.py preserved, fail-closed applied)
- [ ] Steps 2–10 not started
