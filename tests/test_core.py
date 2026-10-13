from agentguard_next import Policy, Decision, evaluate, AuditChain

def test_default_deny():
    assert evaluate(Policy(), "search") is Decision.DENY

def test_allow():
    assert evaluate(Policy(allowed_tools=frozenset({"search"})), "search") is Decision.ALLOW

def test_deny_override():
    p = Policy(frozenset({"search"}), frozenset({"search"}))
    assert evaluate(p, "search") is Decision.DENY

def test_approval():
    p = Policy(allowed_tools=frozenset({"send"}), approval_tools=frozenset({"send"}))
    assert evaluate(p, "send") is Decision.REQUIRE_APPROVAL

def test_empty_tool():
    assert evaluate(Policy(), "") is Decision.DENY

def test_audit_chain():
    chain = AuditChain(b"test-only-key")
    chain.append({"tool": "search", "decision": "allow"})
    chain.append({"tool": "send", "decision": "deny"})
    assert chain.verify()

def test_audit_tamper():
    chain = AuditChain(b"test-only-key")
    chain.append({"tool": "search"})
    chain.entries[0]["event"]["tool"] = "send"
    assert not chain.verify()

def test_audit_key_required():
    try:
        AuditChain(b"").append({"tool":"x"})
    except ValueError:
        pass
    else:
        raise AssertionError("missing key should fail")
