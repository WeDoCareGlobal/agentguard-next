# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Prometheus metrics endpoint (`/metrics`) with HTTP request counters, latency histograms, and tool call tracking
- CI workflow with linting, typechecking, security scanning (bandit, safety, trivy), and coverage enforcement (≥80%)
- Python lockfile (`requirements.lock`) for reproducible builds
- Non-root user in Dockerfile for security hardening
- Base image digest pinning in Dockerfile
- Security scanning in CI (bandit, safety for Python; trivy for container)

### Changed
- Updated Dockerfile to run as non-root user (UID 1000)
- Added tool call metrics instrumentation

### Security
- Added non-root user (UID 1000) in Dockerfile
- Pinned base image digests
- Added security audit steps in CI

## [0.2.0] - 2026-09-30

### Added
- Policy engine with allow/deny lists and rate limiting
- Tamper-evident audit log with hash chain verification
- FastAPI sidecar for tool call authorization
- CLI for policy management
- SQLite + SQLAlchemy persistence
- OpenTelemetry instrumentation

---

**Full Changelog**: https://github.com/we-do-care-global/agentguard/commits/main