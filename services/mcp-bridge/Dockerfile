FROM python:3.11-slim as builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir -e ".[agent,soar,intel,vector,mcp,platform]"

FROM python:3.11-slim

WORKDIR /app

# Copy installed packages
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY frameworks/ /app/frameworks/
COPY services/langgraph/ /app/services/langgraph/
COPY services/mcp-bridge/ /app/services/mcp-bridge/
COPY playbooks/ /app/playbooks/

# Set Python path
ENV PYTHONPATH=/app

# Expose ports
EXPOSE 8000
EXPOSE 8002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the application
CMD ["uvicorn", "services.langgraph.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]