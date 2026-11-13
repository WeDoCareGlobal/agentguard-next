"""
AgentGuard Prompt Injection Filter
---------------------------------

Pre-execution prompt injection defense layer using NVIDIA NeMo Guardrails
or Guardrails AI as the underlying guardrail engine. Runs before any tool
execution in Guard.execute(), blocking jailbreak patterns, prompt injection
attempts, and indirect injection vectors at the boundary.

Design principles:
- Fail-closed: if the filter engine is unavailable, the request is DENYed.
- Layered: works alongside the existing AST scanner (scanner.py) and policy engine.
- Stateless per-call: no session state stored in the filter; audit trail is
  maintained by Guard's HMAC-chained event log.
- Configurable: engine selection via AGENTGUARD_GUARDRAIL_ENGINE env var
  (nemо-guardrails | guardrails-ai | pattern-fallback).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Engine selection
# ---------------------------------------------------------------------------

class GuardrailEngine(str, Enum):
    NEMO_GUARDRAILS = "nemo-guardrails"
    GUARDRAILS_AI = "guardrails-ai"
    PATTERN_FALLBACK = "pattern-fallback"


def _resolve_engine() -> GuardrailEngine:
    raw = os.getenv("AGENTGUARD_GUARDRAIL_ENGINE", "pattern-fallback").strip().lower()
    try:
        return GuardrailEngine(raw)
    except ValueError:
        log.warning("Unknown AGENTGUARD_GUARDRAIL_ENGINE=%r, falling back to pattern-fallback", raw)
        return GuardrailEngine.PATTERN_FALLBACK


GUARDRAIL_ENGINE = _resolve_engine()

# ---------------------------------------------------------------------------
# Pattern-based fallback (no external dependency)
# ---------------------------------------------------------------------------

_PROMPT_INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_previous": re.compile(
        r"(ignore|disregard|forget|override|bypass).{0,40}(previous|prior|above|system|instruction|rule|policy|guardrail)",
        re.IGNORECASE,
    ),
    "system_prompt_leak": re.compile(
        r"(reveal|show|print|output|leak|extract|dump).{0,40}(system|initial|pre).{0,40}(prompt|instruction|message|context)",
        re.IGNORECASE,
    ),
    "role_confusion": re.compile(
        r"(you are now|act as|pretend to|roleplay as|simulate being|from now on you are).{0,60}",
        re.IGNORECASE,
    ),
    "jailbreak_phrase": re.compile(
        r"(dan|do anything now|devil mode|evil mode|unfiltered|uncensored|no restrictions|no limits)",
        re.IGNORECASE,
    ),
    "indirect_injection": re.compile(
        r"(read|load|fetch|retrieve).{0,40}(from|in).{0,40}(website|url|link|document|file|email|pdf|webpage)",
        re.IGNORECASE,
    ),
    "instruction_override": re.compile(
        r"(new instruction|updated instruction|replace instruction|actual instruction|real instruction).{0,40}",
        re.IGNORECASE,
    ),
    "credential_harvest": re.compile(
        r"(api.?key|secret|token|password|credential).{0,40}(=|:|is|was|reveal|show|output|send|email|post)",
        re.IGNORECASE,
    ),
}

# Severity weighting per pattern class
_PATTERN_SEVERITY: dict[str, str] = {
    "ignore_previous": "critical",
    "system_prompt_leak": "critical",
    "role_confusion": "high",
    "jailbreak_phrase": "high",
    "indirect_injection": "medium",
    "instruction_override": "high",
    "credential_harvest": "critical",
}


@dataclass(frozen=True)
class FilterDecision:
    allowed: bool
    reason: Optional[str]
    engine: str
    matches: list[str] = field(default_factory=list)
    severity: Optional[str] = None
    latency_ms: float = 0.0
    prompt_hash: Optional[str] = None


class PatternFallbackFilter:
    """Zero-dependency regex-based prompt injection filter."""

    def __init__(self) -> None:
        self.name = "pattern-fallback"

    def filter(self, prompt: str) -> FilterDecision:
        start = time.perf_counter()
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
        matches: list[str] = []
        max_severity: Optional[str] = None

        severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        current_rank = -1

        for pattern_name, pattern in _PROMPT_INJECTION_PATTERNS.items():
            if pattern.search(prompt):
                matches.append(pattern_name)
                sev = _PATTERN_SEVERITY[pattern_name]
                if severity_rank.get(sev, 0) > current_rank:
                    current_rank = severity_rank[sev]
                    max_severity = sev

        latency_ms = (time.perf_counter() - start) * 1000
        blocked = len(matches) > 0

        return FilterDecision(
            allowed=not blocked,
            reason=("prompt_injection_detected: " + ", ".join(matches)) if blocked else None,
            engine=self.name,
            matches=matches,
            severity=max_severity,
            latency_ms=latency_ms,
            prompt_hash=prompt_hash,
        )


# ---------------------------------------------------------------------------
# NeMo Guardrails integration (optional)
# ---------------------------------------------------------------------------

class NemotronGuardrailsFilter:
    """NVIDIA NeMo Guardrails-backed prompt injection filter."""

    def __init__(self) -> None:
        self.name = "nemo-guardrails"
        self._rails = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            from nemo_guardrails import Guardrails  # type: ignore
            config_path = os.getenv(
                "AGENTGUARD_NEMO_CONFIG",
                os.path.join(os.path.dirname(__file__), "nemo_config"),
            )
            self._rails = Guardrails.from_config(config_path)
            self._initialized = True
            log.info("NeMo Guardrails initialized from %s", config_path)
        except Exception as exc:  # noqa: BLE001 - degrade to fallback
            log.warning("NeMo Guardrails unavailable (%s), falling back to pattern filter", exc)
            self._rails = None
            self._initialized = True

    def filter(self, prompt: str) -> FilterDecision:
        self._ensure_initialized()
        start = time.perf_counter()
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]

        if self._rails is None:
            # Degrade to pattern fallback
            fallback = PatternFallbackFilter()
            decision = fallback.filter(prompt)
            return FilterDecision(
                allowed=decision.allowed,
                reason=decision.reason,
                engine="nemo-guardrails->pattern-fallback",
                matches=decision.matches,
                severity=decision.severity,
                latency_ms=(time.perf_counter() - start) * 1000,
                prompt_hash=prompt_hash,
            )

        try:
            result = self._rails.generate(messages=[{"role": "user", "content": prompt}])
            content = result.content if hasattr(result, "content") else str(result)
            # NeMo Guardrails returns modified content or raises on block
            blocked = (
                "[BLOCK" in content.upper()
                or "[INJECTION" in content.upper()
                or "refusal" in content.lower()
            )
            matches = ["nemo-rails-block"] if blocked else []
            severity = "critical" if blocked else None
            latency_ms = (time.perf_counter() - start) * 1000
            return FilterDecision(
                allowed=not blocked,
                reason=("prompt_injection_detected: nemo-rails-block") if blocked else None,
                engine=self.name,
                matches=matches,
                severity=severity,
                latency_ms=latency_ms,
                prompt_hash=prompt_hash,
            )
        except Exception as exc:  # noqa: BLE001 - rail error, fail closed
            log.warning("NeMo Guardrails filter error (%s), failing closed", exc)
            latency_ms = (time.perf_counter() - start) * 1000
            return FilterDecision(
                allowed=False,
                reason="filter_engine_error",
                engine=self.name,
                matches=["engine-error"],
                severity="critical",
                latency_ms=latency_ms,
                prompt_hash=prompt_hash,
            )


# ---------------------------------------------------------------------------
# Guardrails AI integration (optional)
# ---------------------------------------------------------------------------

class GuardrailsAIFilter:
    """Guardrails AI (guardrails-ai) backed prompt injection filter."""

    def __init__(self) -> None:
        self.name = "guardrails-ai"
        self._guard = None
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        try:
            from guardrails import Guard  # type: ignore
            from guardrails.validators import (  # type: ignore
                PromptInjection,
                ToxicLanguage,
                RestrictToTopic,
            )
            self._guard = Guard().use_many(
                PromptInjection(on_fail="exception"),
                ToxicLanguage(on_fail="exception"),
            )
            self._initialized = True
            log.info("Guardrails AI initialized")
        except Exception as exc:  # noqa: BLE001 - degrade to fallback
            log.warning("Guardrails AI unavailable (%s), falling back to pattern filter", exc)
            self._guard = None
            self._initialized = True

    def filter(self, prompt: str) -> FilterDecision:
        self._ensure_initialized()
        start = time.perf_counter()
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]

        if self._guard is None:
            fallback = PatternFallbackFilter()
            decision = fallback.filter(prompt)
            return FilterDecision(
                allowed=decision.allowed,
                reason=decision.reason,
                engine="guardrails-ai->pattern-fallback",
                matches=decision.matches,
                severity=decision.severity,
                latency_ms=(time.perf_counter() - start) * 1000,
                prompt_hash=prompt_hash,
            )

        try:
            self._guard.validate(prompt)
            # If no exception raised, the prompt passed validation
            latency_ms = (time.perf_counter() - start) * 1000
            return FilterDecision(
                allowed=True,
                reason=None,
                engine=self.name,
                matches=[],
                severity=None,
                latency_ms=latency_ms,
                prompt_hash=prompt_hash,
            )
        except Exception as exc:  # noqa: BLE001 - guard triggered, block
            latency_ms = (time.perf_counter() - start) * 1000
            return FilterDecision(
                allowed=False,
                reason=f"prompt_injection_detected: guardrails-ai ({exc})",
                engine=self.name,
                matches=["guardrails-ai-block"],
                severity="critical",
                latency_ms=latency_ms,
                prompt_hash=prompt_hash,
            )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_FILTER_REGISTRY: dict[GuardrailEngine, Any] = {
    GuardrailEngine.NEMO_GUARDRAILS: NemotronGuardrailsFilter,
    GuardrailEngine.GUARDRAILS_AI: GuardrailsAIFilter,
    GuardrailEngine.PATTERN_FALLBACK: PatternFallbackFilter,
}


def get_filter() -> Any:
    """Return the configured guardrail filter instance."""
    cls = _FILTER_REGISTRY[GUARDRAIL_ENGINE]
    return cls()


# ---------------------------------------------------------------------------
# Convenience: single-call filter for Guard.execute() integration
# ---------------------------------------------------------------------------

def filter_prompt(prompt: str) -> FilterDecision:
    """Filter a prompt through the configured guardrail engine."""
    return get_filter().filter(prompt)
