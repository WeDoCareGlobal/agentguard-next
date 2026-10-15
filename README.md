# AgentGuard — Security & Governance Control Plane for Autonomous AI Agents

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22945778.svg)](https://doi.org/10.5281/zenodo.22945778)
[![ORCID](https://img.shields.io/badge/ORCID-0009--0009--8515--2727-green.svg)](https://orcid.org/0009-0009-8515-2727)
[![We Do Care Global](https://img.shields.io/badge/We%20Do%20Care%20Global-Enterprise%20AI%20Governance-purple.svg)](https://wedocare-global.com/)

**Part of the [We Do Care Global](https://wedocare-global.com/) ecosystem — 6 published systems, Apache-2.0 open source, 33% profits → humanitarian.**

---

## Overview

AgentGuard is a **policy-aware agent control plane** with auditable decisions, explicit boundaries, and human oversight built into the architecture — not bolted on after the fact.

This repository contains the **next-generation architecture** (Python 3.11+):
- **PostgreSQL-backed coordination** — distributed approvals, kill-switch, reservations
- **OIDC identity integration** — enterprise authentication
- **Centralized HMAC audit log** — tamper-evident, append-only
- **CLI & policy-as-code** — `policy.yaml` for declarative guardrails
- **Docker/Compose ready** — production deployment in minutes

---

## Capabilities

| Layer | Features |
|-------|----------|
| **Policy Engine** | Default-deny, explicit tool registry, deny precedence, per-agent rate limits |
| **Approval Flow** | Bound, single-use, expiring tokens; human-in-the-loop; admin-only issuance |
| **Replay Protection** | Durable request IDs, HMAC-chained audit log, verification CLI |
| **Kill Switch** | Instant halt across all agents via PostgreSQL coordination |
| **Identity** | OIDC/OAuth2 integration, API key management, vault-backed secrets |
| **Audit** | Centralized PostgreSQL audit with HMAC chaining; tail-truncation detection |
| **Observability** | Structured logs, metrics, health endpoints for Command Center |

---

## Quick Start

### 1. Install
```bash
pip install -e .
# or with PostgreSQL support
pip install -e ".[postgres]"
```

### 2. Configure Policy
```bash
cp policy.example.yaml policy.yaml
# edit policy.yaml — define tools, rate limits, approval rules
```

### 3. Run via Docker Compose (recommended)
```bash
docker-compose up -d
# API at http://localhost:8000
# Health at http://localhost:8000/health
```

### 4. Or run locally
```bash
# Start PostgreSQL (required for coordination/audit)
docker run -d --name pg -e POSTGRES_PASSWORD=guard -p 5432:5432 postgres:16

# Run API server
agentguard serve --policy policy.yaml --pg-dsn postgresql://postgres:guard@localhost/guard
```

### 5. Use CLI
```bash
# Verify audit chain
agentguard audit verify --db audit.sqlite

# Issue approval token
agentguard approve --agent my-agent --tool dangerous_tool --ttl 300

# Check rate limits
agentguard limits --agent my-agent
```

---

## Architecture

```
agentguard/
├── api.py              # FastAPI HTTP endpoints
├── central_audit.py    # PostgreSQL HMAC audit adapter
├── cli.py              # Typer CLI (policy, audit, approve, limits)
├── console.py          # Rich console output
├── coordination.py     # Distributed coordination (PostgresCoordinator)
├── core.py             # Guard core: policy eval, approval, kill-switch
├── identity.py         # OIDC/OAuth2, API keys
├── main.py             # Entry point: serve, CLI
├── models.py           # Pydantic models
├── oidc.py             # OIDC provider integration
├── postgres.py         # PostgreSQL connection pool
├── policy.py           # Policy loading/validation (YAML)
├── shared_control.py   # Shared halt/approvals
├── vault.py            # Secrets vault interface
└── vault_http.py       # HTTP vault client
```

---

## Policy Example (`policy.yaml`)

```yaml
version: 1
default: deny
tools:
  - name: "read_file"
    allow: true
    rate_limit: 100/min
  - name: "write_file"
    allow: false  # requires approval
    approval:
      ttl_seconds: 300
      max_uses: 1
  - name: "execute_command"
    allow: false
    approval:
      ttl_seconds: 60
      max_uses: 1
      requires_admin: true
agents:
  "research-agent":
    tools: ["read_file", "web_search"]
    rate_limit: 50/min
  "coding-agent":
    tools: ["read_file", "write_file", "execute_command"]
    rate_limit: 20/min
```

---

## Docker Compose

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_DB: guard
      POSTGRES_PASSWORD: guard
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

  agentguard:
    build: .
    ports:
      - "8000:8000"
    environment:
      PG_DSN: postgresql://postgres:guard@postgres/guard
      POLICY_PATH: /app/policy.yaml
      VAULT_URL: http://vault:8200
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./policy.yaml:/app/policy.yaml:ro

  vault:
    image: hashicorp/vault:1.15
    cap_add:
      - IPC_LOCK
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: root
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    ports:
      - "8200:8200"

volumes:
  pgdata:
```

---

## Testing

```bash
# Unit tests
pytest tests/ -v --cov=agentguard --cov-report=term-missing

# Integration tests (requires PostgreSQL)
pytest tests/ -v -m integration

# Security scans
bandit -r agentguard/
safety check
ruff check agentguard/
mypy agentguard/
```

---

## CI/CD

- **CI** (`.github/workflows/ci.yml`): lint, typecheck, security scan, test with coverage ≥80%
- **Security** (`.github/workflows/security.yml`): Trivy filesystem scan
- **Docker** (`.github/workflows/docker.yml`): multi-arch build, push to GHCR
- **Pages** (`.github/workflows/pages.yml`): deploy `docs/` to GitHub Pages
- **Zenodo** (`.github/workflows/zenodo.yml`): archive releases to Zenodo, mint DOI, push to ORCID

---

## Release & Archival

Every GitHub release is automatically archived to **Zenodo** (DataCite DOI) and pushed to **ORCID** (0009-0009-8515-2727).

```bash
# Create release
git tag v1.0.0
git push origin v1.0.0
gh release create v1.0.0 --generate-notes
# → triggers Zenodo workflow → mints DOI → updates ORCID
```

---

## WDCG Ecosystem

| System | Repo | Purpose |
|--------|------|---------|
| **AgentGuard** | `WeDoCareGlobal/agentguard-next` | Security & governance control plane |
| **FoundationCentar** | `WeDoCareGlobal/FoundationCentar-Next` | Governance frameworks |
| **Enterprise Hybrid-RAG** | `WeDoCareGlobal/enterprise-hybrid-rag-next` | Hybrid retrieval |
| **Agent Eval** | `WeDoCareGlobal/agent-eval-next` | Evaluation harness |
| **AgentVault** | `WeDoCareGlobal/AgentVault-Next` | Tool registry & assurance |
| **Pharma Intelligence OS** | `WeDoCareGlobal/Pharma-Intelligence-Os-Next` | Regulatory intelligence |

---

## License

Apache-2.0 © 2026 [We Do Care Global](https://wedocare-global.com/) — Emir Perla (ORCID: 0009-0009-8515-2727)

33% of profits → humanitarian aid.

---

## Citation

```bibtex
@software{perla2026agentguard,
  author = {Perla, Emir},
  title = {AgentGuard – Security & Governance Control Plane for Autonomous AI Agents},
  version = {1.0.0rc1},
  year = {2026},
  doi = {10.5281/zenodo.22945778},
  url = {https://github.com/WeDoCareGlobal/agentguard-next}
}
```
