"""Tests for the AgentGuard security scanner.

Two properties are pinned down here:

1.  Real dangerous call sites ARE reported (no regression to a blind scanner).
2.  Identifiers that merely *look* dangerous — inside strings, comments,
    docstrings, or as part of a longer identifier such as a test function
    named ``test_policy_load_and_eval`` — are NOT reported.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCANNER = Path(__file__).resolve().parents[1] / "agentguard" / "scanner.py"


def scan_source(tmp_path: Path, source: str) -> list[dict]:
    """Write *source* to a temp file and return the scanner's JSON findings."""
    target = tmp_path / "sample.py"
    target.write_text(source, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCANNER), "scan", str(target), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), f"scanner crashed: {proc.stderr}"
    return json.loads(proc.stdout)


# --------------------------------------------------------------------------
# 1. Real dangerous calls must still be caught
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source,expected_match",
    [
        ("result = eval(user_input)\n", "eval"),
        ("exec(compiled_code)\n", "exec"),
        ("import os\nos.system('rm -rf /')\n", "os.system"),
        ("import subprocess\nsubprocess.run(cmd, shell=True)\n", "subprocess.run"),
        ("import subprocess\nsubprocess.Popen(cmd, shell=True)\n", "subprocess.Popen"),
        ("import pickle\npickle.loads(blob)\n", "pickle.loads"),
        ("value = compile(src, '', 'exec')\n", "compile"),
        ("mod = __import__('os')\n", "__import__"),
    ],
)
def test_real_dangerous_calls_are_detected(tmp_path, source, expected_match):
    findings = scan_source(tmp_path, source)
    assert findings, f"expected a finding for {expected_match!r}"
    assert findings[0]["severity"] == "critical"
    assert expected_match in findings[0]["match"]


def test_shell_true_kwarg_is_detected(tmp_path):
    """shell=True on a call that is not otherwise flagged must still be caught."""
    source = "run_task(['ls'], shell=True)\n"
    findings = scan_source(tmp_path, source)
    assert findings
    assert "shell=True" in findings[0]["match"]


def test_subprocess_run_is_flagged_regardless_of_kwargs(tmp_path):
    source = "import subprocess\nsubprocess.run(['ls'], shell=True)\n"
    findings = scan_source(tmp_path, source)
    assert findings
    assert findings[0]["match"] == "subprocess.run"


# --------------------------------------------------------------------------
# 2. False positives must not be reported
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        # The word "eval" inside prose / docstrings / comments.
        '"""YAML policy loader, evaluator, and rate limiter."""\n',
        "# policy evaluation, and the refusal is audited\n",
        'msg = "please evaluate this policy"\n',
        # A test whose *name* contains eval.
        "def test_policy_load_and_eval(tmp_path):\n    pass\n",
        # The scanner's own pattern definitions, which mention these names.
        'PATTERN = r"(eval|exec|subprocess|os.system|shell=True)"\n',
        # Attribute access without a call.
        "value = obj.eval\n",
        # A local variable that shadows nothing dangerous.
        "evaluation_results = compute()\n",
    ],
)
def test_benign_identifiers_are_not_reported(tmp_path, source):
    findings = scan_source(tmp_path, source)
    critical = [f for f in findings if f["severity"] == "critical"]
    assert not critical, f"false positive critical findings: {critical}"


def test_scanner_does_not_flag_itself(tmp_path):
    """Scanning the scanner's own source must produce no critical findings."""
    findings = scan_source(tmp_path, SCANNER.read_text(encoding="utf-8"))
    critical = [f for f in findings if f["severity"] == "critical"]
    assert not critical, f"scanner flagged itself: {critical}"


def test_scanned_source_tree_is_clean(tmp_path):
    """The project's own package must scan clean of critical findings."""
    pkg = Path(__file__).resolve().parents[1] / "agentguard"
    proc = subprocess.run(
        [sys.executable, str(SCANNER), "scan", str(pkg), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), f"scanner crashed: {proc.stderr}"
    findings = json.loads(proc.stdout)
    critical = [f for f in findings if f["severity"] == "critical"]
    assert not critical, f"package flagged: {critical}"
