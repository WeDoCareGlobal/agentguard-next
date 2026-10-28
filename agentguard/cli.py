"""Typer‑based CLI for agentguard."""
from __future__ import annotations

import os
from pathlib import Path

import typer
import uvicorn
import yaml

from .models import Limits, Policy
from .policy import load_policy

app = typer.Typer(add_completion=False, help="agentguard CLI")
# Back-compat alias: earlier docs/READMEs refer to `cli`.
cli = app

_DEFAULT_POLICY_PATH = "policy.yaml"
_DEFAULT_RUN_HOST = "0.0.0.0"  # nosec B104 - explicitly exposed server default, configurable via --host
_DEFAULT_RUN_PORT = 8000
_DEFAULT_RUN_POLICY = "policy.yaml"

# B008: Typer option instances must be module-level singletons, not recreated on each call.
_OPT_AGENT = typer.Option(..., help="Agent name, e.g. research-bot")
_OPT_OUT = typer.Option(_DEFAULT_POLICY_PATH, help="Where to write example policy")
_OPT_MAX_CPM = typer.Option(60, help="Enforced rate limit: max tool calls per minute (0 = unlimited)")
_OPT_POLICY = typer.Option(_DEFAULT_RUN_POLICY, help="Path to policy YAML")
_OPT_HOST = typer.Option(_DEFAULT_RUN_HOST, help="Host to bind")
_OPT_PORT = typer.Option(_DEFAULT_RUN_PORT, help="Port to bind")
_OPT_RELOAD = typer.Option(False, help="Enable uvicorn reload (dev)")


@app.command()
def init(
    agent: str = _OPT_AGENT,
    out: Path = _OPT_OUT,
    max_cpm: int = _OPT_MAX_CPM,
):
    """Create a starter policy.yaml."""
    example = Policy(
        agent=agent,
        allowed_tools=["web_search", "read_file"],
        denied_tools=["send_email", "transfer_funds"],
        limits=Limits(
            max_calls_per_minute=max_cpm or None,
            max_usd_per_day=5.00,
            max_tokens_per_call=4000,
        ),
    )
    out.write_text(yaml.dump(example.model_dump(), sort_keys=False))
    limit_note = f"{max_cpm}/min" if max_cpm else "no rate limit"
    typer.secho(f"✅ Example policy written to {out} (rate limit: {limit_note})", fg=typer.colors.GREEN)


@app.command()
def run(
    policy: Path = _OPT_POLICY,
    host: str = _OPT_HOST,
    port: int = _OPT_PORT,
    reload: bool = _OPT_RELOAD,
):
    """Run the agentguard FastAPI server."""
    # Validate policy early
    try:
        load_policy(policy)
    except Exception as e:  # noqa: BLE001 - fail early on any policy error
        typer.secho(f"❌ Invalid policy: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    typer.secho(f"🚀 Starting agentguard on http://{host}:{port}", fg=typer.colors.BLUE)
    # uvicorn.run() has no `env` parameter: set it in the process environment
    # so agentguard.main picks the policy path up at import time.
    os.environ["AGENTGUARD_POLICY"] = str(policy)
    uvicorn.run(
        "agentguard.main:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    app()
