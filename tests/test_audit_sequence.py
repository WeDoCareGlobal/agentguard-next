"""Regression tests for local audit chain continuity."""
from agentguard.core import Guard, Policy


def test_audit_verifier_detects_missing_middle_record(tmp_path):
    guard = Guard(str(tmp_path / "audit.db"), b"a" * 32,
                  Policy(frozenset({"read"})), {"read": lambda _: {"ok": True}})
    guard.set_kill_switch(False)
    guard.set_kill_switch(False)
    guard.set_kill_switch(False)
    assert guard.verify_audit()
    guard.db.execute("DELETE FROM events WHERE seq=2")
    assert not guard.verify_audit()


def test_audit_verifier_detects_modified_record(tmp_path):
    guard = Guard(str(tmp_path / "audit.db"), b"a" * 32,
                  Policy(frozenset({"read"})), {"read": lambda _: {"ok": True}})
    guard.set_kill_switch(False)
    assert guard.verify_audit()
    guard.db.execute("UPDATE events SET body='changed' WHERE seq=1")
    assert not guard.verify_audit()
