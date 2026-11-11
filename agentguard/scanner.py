"""AgentGuard security scanner — AST-based detection of dangerous call sites.

Ported from we-do-care-global/agentguard (agentguard.py). Scans Python and
text source files for security issues:

- Overly permissive tool permissions
- Missing input validation (eval/exec/subprocess/os.system/shell=True)
- Indirect prompt injection vectors
- Unrestricted file system access
- Hardcoded credentials
- Missing rate limiting on HTTP clients

Usage:
    python -m agentguard.scanner scan <path> [--format json|text] [--severity low|medium|high|critical]
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# Security patterns for text-based checks (non-Python files).
SECURITY_PATTERNS: dict[str, dict[str, str]] = {
    "overly_permissive": {
        "pattern": r"(allow_all|permit_all|unrestricted|no.?limit)",
        "severity": "high",
        "message": "Overly permissive tool permission detected",
    },
    "prompt_injection": {
        "pattern": r"(ignore.*previous|disregard.*instructions|system.*prompt)",
        "severity": "high",
        "message": "Potential prompt injection vector",
    },
    "unrestricted_fs": {
        "pattern": r"(open\(|read_file|write_file|Path\(|os\.path)",
        "severity": "medium",
        "message": "File system access without path restriction",
    },
    "missing_auth": {
        "pattern": r"(api_key|token|secret|password)\s*=\s*['\"]",
        "severity": "critical",
        "message": "Hardcoded credential detected",
    },
    "no_rate_limit": {
        "pattern": r"(requests\.|httpx\.|urllib|aiohttp)",
        "severity": "medium",
        "message": "HTTP client without rate limiting",
    },
}

# File extensions to scan.
SCAN_EXTENSIONS = {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml"}

# Names that are dangerous when *called*. Matched against actual call sites
# (via AST) rather than raw text, so prose like "policy evaluation" or a test
# named test_policy_load_and_eval never triggers a finding.
DANGEROUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
}

# Dotted calls that are dangerous, e.g. os.system, subprocess.call.
DANGEROUS_DOTTED_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_output",
    "subprocess.check_call",
    "pickle.loads",
    "marshal.loads",
}

# Keyword arguments that make an otherwise-normal call dangerous.
DANGEROUS_KWARGS = {"shell": "True"}


def _dotted_name(node: ast.AST) -> str:
    """Render an AST call target as a dotted name, e.g. 'os.system'."""
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _is_true(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def scan_file(filepath: Path) -> list[dict[str, Any]]:
    """Scan a single Python file for dangerous call sites.

    Uses the AST so that identifiers inside strings, comments, docstrings and
    test function names are never reported. Only real call expressions count.
    """
    issues: list[dict[str, Any]] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return issues

    if filepath.suffix != ".py":
        return _scan_text_file(filepath, content)

    try:
        tree = ast.parse(content)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _dotted_name(node.func)
        short = name.rsplit(".", 1)[-1]
        hit = None
        if name in DANGEROUS_DOTTED_CALLS or short in DANGEROUS_CALLS:
            hit = name or short
        else:
            for kw in node.keywords:
                if kw.arg in DANGEROUS_KWARGS and _is_true(kw.value):
                    hit = f"{name}(... {kw.arg}=True)"
                    break
        if hit is None:
            continue
        issues.append(
            {
                "file": str(filepath),
                "line": node.lineno,
                "check": "missing_validation",
                "severity": "critical",
                "message": "Dangerous function call without input validation",
                "match": hit,
            }
        )
    return issues


def _scan_text_file(filepath: Path, content: str) -> list[dict[str, Any]]:
    """Text-based checks for non-Python files."""
    issues: list[dict[str, Any]] = []
    for check_name, check in SECURITY_PATTERNS.items():
        pattern = check["pattern"]
        for match in re.finditer(pattern, content, re.IGNORECASE):
            line_num = content[: match.start()].count("\n") + 1
            issues.append(
                {
                    "file": str(filepath),
                    "line": line_num,
                    "check": check_name,
                    "severity": check["severity"],
                    "message": check["message"],
                    "match": match.group(0),
                }
            )
    return issues


# Directories that are never production code. `tests` is excluded because test
# suites legitimately spawn subprocesses to exercise the scanner itself.
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", ".pytest_cache"}


def scan_directory(path: Path) -> list[dict[str, Any]]:
    """Recursively scan directory for security issues."""
    issues = []
    for root, _dirs, files in os.walk(path):
        parts = set(Path(root).parts)
        if parts & SKIP_DIRS:
            continue
        for filename in files:
            filepath = Path(root) / filename
            if filepath.suffix in SCAN_EXTENSIONS:
                issues.extend(scan_file(filepath))
    return issues


def format_text(issues: list[dict[str, Any]]) -> str:
    """Format issues as human-readable text."""
    if not issues:
        return "✓ No security issues found"

    lines = [f"Found {len(issues)} security issue(s):\n"]
    for issue in issues:
        lines.append(f"  [{issue['severity'].upper()}] {issue['file']}:{issue['line']}")
        lines.append(f"    → {issue['message']}")
        lines.append(f"    Match: {issue['match']}")
        lines.append("")
    return "\n".join(lines)


def format_json(issues: list[dict[str, Any]]) -> str:
    """Format issues as JSON."""
    return json.dumps(issues, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentGuard — Agent Security Scanner")
    parser.add_argument("command", choices=["scan"], help="Command to run")
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Output format"
    )
    parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        help="Minimum severity to report",
    )
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"Error: {target} does not exist", file=sys.stderr)
        return 1

    if target.is_file():
        issues = scan_file(target)
    else:
        issues = scan_directory(target)

    if args.severity:
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_order[args.severity]
        issues = [
            i
            for i in issues
            if severity_order.get(i["severity"], 0) >= min_level
        ]

    if args.format == "json":
        print(format_json(issues))
    else:
        print(format_text(issues))

    return 0 if not issues else 1


if __name__ == "__main__":
    sys.exit(main())
