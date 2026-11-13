"""
AgentGuard OpenTelemetry instrumentation
----------------------------------------

Distributed tracing for LLM agent workflows across the WDCG 7-system portfolio.
Exports traces via OTLP to Langfuse, Arize Phoenix, or any OTLP-compatible backend.

Usage:
    from agentguard.telemetry import setup_telemetry, trace_llm_call, trace_tool_call

    tracer = setup_telemetry(service_name="agentguard", otlp_endpoint="http://localhost:4318")

    with trace_llm_call(tracer, model="gpt-4o", prompt="...") as span:
        response = llm.complete(prompt)
        span.set_attribute("llm.response_tokens", len(response))

    with trace_tool_call(tracer, tool="read_file", agent="agent-1") as span:
        result = tool.execute()
        span.set_attribute("tool.result_size", len(result))
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from typing import Any, Optional, Iterator

# ---------------------------------------------------------------------------
# Optional OpenTelemetry import — gracefully degrades if not installed
# ---------------------------------------------------------------------------

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.trace.export import ConsoleSpanExporter
    from opentelemetry.trace import Status, StatusCode

    _OTEL_AVAILABLE = True
except Exception:  # noqa: BLE001 — opentelemetry may not be installed in all envs
    trace = None  # type: ignore
    TracerProvider = None  # type: ignore
    BatchSpanProcessor = None  # type: ignore
    Resource = None  # type: ignore
    OTLPSpanExporter = None  # type: ignore
    ConsoleSpanExporter = None  # type: ignore
    Status = None  # type: ignore
    StatusCode = None  # type: ignore
    _OTEL_AVAILABLE = False


class _NullSpan:
    """No-op span used when OpenTelemetry is not available."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def add_event(self, name: str, attributes: Optional[dict[str, Any]] = None) -> None:
        pass

    def end(self) -> None:
        pass

    def is_recording(self) -> bool:
        return False


_tracer: Optional[Any] = None
_provider: Optional[Any] = None


def setup_telemetry(
    service_name: str = "agentguard",
    service_version: str = "1.0.0",
    otlp_endpoint: Optional[str] = None,
    console_export: bool = False,
) -> trace.Tracer:
    """
    Initialize OpenTelemetry tracing.

    Reads AGENTGUARD_OTLP_ENDPOINT from environment if otlp_endpoint not provided.
    Returns a tracer instance for creating spans.
    """
    global _tracer, _provider

    if _tracer is not None:
        return _tracer

    if not _OTEL_AVAILABLE or trace is None or Resource is None:
        # Return a no-op tracer that produces null spans
        class _NoOpTracer:
            def start_span(self, name: str, attributes: Optional[dict] = None) -> _NullSpan:
                return _NullSpan()

        _tracer = _NoOpTracer()
        return _tracer

    endpoint = otlp_endpoint or os.getenv("AGENTGUARD_OTLP_ENDPOINT") or os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": service_version,
            "service.namespace": "wedocare-global",
        }
    )

    provider = TracerProvider(resource=resource)

    if endpoint:
        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
    elif console_export:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)
    _provider = provider
    _tracer = trace.get_tracer(service_name, service_version)

    return _tracer


def get_tracer() -> Optional[trace.Tracer]:
    """Return the configured tracer, or None if not initialized."""
    return _tracer or trace.get_tracer("agentguard")


@contextmanager
def trace_llm_call(
    tracer: trace.Tracer,
    model: str,
    prompt: str,
    agent: Optional[str] = None,
    request_id: Optional[str] = None,
    **extra_attributes: Any,
) -> Iterator[Any]:
    """
    Trace an LLM completion call. Sets standard LLM semantic convention attributes.
    """
    span = tracer.start_span(
        name="llm.call",
        attributes={
            "llm.model": model,
            "llm.prompt": prompt[:1000],  # truncate for safety
            "llm.prompt_length": len(prompt),
            **({"agent.name": agent} if agent else {}),
            **({"request.id": request_id} if request_id else {}),
            **extra_attributes,
        },
    )
    start = time.perf_counter()
    try:
        yield span
    except Exception as exc:
        span.set_status(Status(StatusCode.ERROR, str(exc)))
        span.set_attribute("llm.error", str(exc))
        raise
    finally:
        span.set_attribute("llm.latency_ms", (time.perf_counter() - start) * 1000)
        span.end()


@contextmanager
def trace_tool_call(
    tracer: trace.Tracer,
    tool: str,
    agent: str,
    request_id: Optional[str] = None,
    **extra_attributes: Any,
) -> Iterator[Any]:
    """
    Trace an agent tool execution call.
    """
    span = tracer.start_span(
        name="tool.call",
        attributes={
            "tool.name": tool,
            "agent.name": agent,
            **({"request.id": request_id} if request_id else {}),
            **extra_attributes,
        },
    )
    start = time.perf_counter()
    try:
        yield span
    except Exception as exc:
        span.set_status(Status(StatusCode.ERROR, str(exc)))
        span.set_attribute("tool.error", str(exc))
        raise
    finally:
        span.set_attribute("tool.latency_ms", (time.perf_counter() - start) * 1000)
        span.end()


@contextmanager
def trace_retrieval(
    tracer: trace.Tracer,
    query: str,
    retriever: str,
    agent: Optional[str] = None,
    **extra_attributes: Any,
) -> Iterator[Any]:
    """
    Trace a RAG retrieval call (for Enterprise Hybrid-RAG).
    """
    span = tracer.start_span(
        name="retrieval.call",
        attributes={
            "retrieval.query": query[:1000],
            "retrieval.retriever": retriever,
            "retrieval.query_length": len(query),
            **({"agent.name": agent} if agent else {}),
            **extra_attributes,
        },
    )
    start = time.perf_counter()
    try:
        yield span
    except Exception as exc:
        span.set_status(Status(StatusCode.ERROR, str(exc)))
        span.set_attribute("retrieval.error", str(exc))
        raise
    finally:
        span.set_attribute("retrieval.latency_ms", (time.perf_counter() - start) * 1000)
        span.end()


@contextmanager
def trace_evaluation(
    tracer: trace.Tracer,
    evaluator: str,
    agent: Optional[str] = None,
    **extra_attributes: Any,
) -> Iterator[Any]:
    """
    Trace an Agent Eval evaluation call.
    """
    span = tracer.start_span(
        name="evaluation.call",
        attributes={
            "evaluation.evaluator": evaluator,
            **({"agent.name": agent} if agent else {}),
            **extra_attributes,
        },
    )
    start = time.perf_counter()
    try:
        yield span
    except Exception as exc:
        span.set_status(Status(StatusCode.ERROR, str(exc)))
        span.set_attribute("evaluation.error", str(exc))
        raise
    finally:
        span.set_attribute("evaluation.latency_ms", (time.perf_counter() - start) * 1000)
        span.end()


@contextmanager
def trace_agent_workflow(
    tracer: trace.Tracer,
    workflow: str,
    agent: str,
    request_id: Optional[str] = None,
    **extra_attributes: Any,
) -> Iterator[Any]:
    """
    Trace a full agent workflow span (FoundationCentar / orchestrator).
    """
    span = tracer.start_span(
        name="agent.workflow",
        attributes={
            "workflow.name": workflow,
            "agent.name": agent,
            **({"request.id": request_id} if request_id else {}),
            **extra_attributes,
        },
    )
    start = time.perf_counter()
    try:
        yield span
    except Exception as exc:
        span.set_status(Status(StatusCode.ERROR, str(exc)))
        span.set_attribute("workflow.error", str(exc))
        raise
    finally:
        span.set_attribute("workflow.latency_ms", (time.perf_counter() - start) * 1000)
        span.end()


def set_span_attribute(span: Any, key: str, value: Any) -> None:
    """Safely set an attribute on a span if it is recording."""
    if span is not None and span.is_recording():
        span.set_attribute(key, value)


def add_span_event(span: Any, name: str, attributes: Optional[dict[str, Any]] = None) -> None:
    """Safely add an event to a span if it is recording."""
    if span is not None and span.is_recording():
        span.add_event(name, attributes or {})
