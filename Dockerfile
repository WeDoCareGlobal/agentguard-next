FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1

WORKDIR /app

# System deps needed for building some wheels
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --no-create-home --shell /bin/bash --uid 1000 appuser

# Copy source
COPY pyproject.toml .
COPY requirements.lock .
COPY README.md .
COPY LICENSE .
COPY agentguard/ ./agentguard/
COPY tests/ ./tests/

# Install package (no cache to keep image small)
RUN pip install --no-cache-dir --break-system-packages -e . -r requirements.lock

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose API port
EXPOSE 8000

# Default command (overridden by docker-compose)
CMD ["agentguard", "run", "--policy", "/app/policy.yaml"]
