# Enterprise AI OS — RC1 integration track

Status: PROPOSED / NOT PRODUCTION VERIFIED

This branch is isolated from main. Do not merge until the integration and security gates pass.

## Target architecture
- OmniGuard: request inspection, policy preflight and security event metadata.
- AgentGuard: authoritative execution authorization and tool policy enforcement.
- FoundationCentar: orchestration and approval workflow.
- AgentVault: secrets and credential lifecycle.
- Hybrid RAG: ACL-aware knowledge retrieval.
- Agent Eval: repeatable evaluations and telemetry.
- Pharma Intelligence OS: domain workflows with human review.

## Contract to reconcile
FoundationCentar currently calls /toolcall while AgentGuard has exposed /v1/execute. Define a versioned adapter or common API contract; do not silently bypass policy checks.

## Non-negotiable release gates
1. Preserve tenant identity across every hop.
2. Fail closed for high-risk tool execution if security services are unavailable.
3. Verify approval tokens and persist security audit events durably.
4. Replace development API keys and validate authorization end-to-end.
5. Execute fresh CI tests, adversarial evaluations and recovery scenarios.
6. Produce SBOM, pinned dependency manifests, rollback plan and staging evidence.

## Merge policy
No automatic merge to main. Review each change through a pull request after tests and human approval.

## Provenance
Integration branch created from the original repository main on 2026-10-15. The original main remains unchanged.
