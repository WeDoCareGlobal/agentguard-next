# TODO: pin to a verified multi-platform digest after a successful image build.
FROM python:3.12-slim

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

# Install package (no cache to keep image small)
RUN pip install --no-cache-dir -e . -r requirements.lock

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose API port
EXPOSE 8000

# Default command (overridden by docker-compose)
CMD ["agentguard", "run", "--policy", "/app/policy.yaml"]
