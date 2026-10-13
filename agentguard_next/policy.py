from dataclasses import dataclass, field
from enum import Enum

class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"

@dataclass(frozen=True)
class Policy:
    allowed_tools: frozenset[str] = field(default_factory=frozenset)
    denied_tools: frozenset[str] = field(default_factory=frozenset)
    approval_tools: frozenset[str] = field(default_factory=frozenset)

def evaluate(policy: Policy, tool: str) -> Decision:
    if not isinstance(tool, str) or not tool.strip():
        return Decision.DENY
    if tool in policy.denied_tools:
        return Decision.DENY
    if tool not in policy.allowed_tools:
        return Decision.DENY
    if tool in policy.approval_tools:
        return Decision.REQUIRE_APPROVAL
    return Decision.ALLOW
