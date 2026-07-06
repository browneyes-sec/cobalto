"""
Cobalto LangGraph Agent API

Entry point for the SOC agent orchestration service.
Integrates authentication, audit logging, rate limiting, input validation,
and Prometheus metrics into the LangGraph agent workflow.

Endpoints:
  POST /agent/analyze     - Analyze a security alert through the agent pipeline
  GET  /health            - Liveness probe
  GET  /ready             - Readiness probe
  GET  /metrics           - Prometheus metrics
  GET  /graph/visualize   - Agent graph visualization (Mermaid)
"""

import uuid
import os
import time
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

from state import AlertPayload
from graph import agent
from middleware.auth import AuthMiddleware
from middleware.audit import AuditLogger
from middleware.rate_limiter import RateLimiter
from middleware.validator import InputValidator
from config.settings import settings

# ── Application Setup ───────────────────────────────────────────────

app = FastAPI(
    title="Cobalto SOC LangGraph Agent",
    version="1.0.0",
    description="Agentic SOC/MDR alert analysis platform",
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware Initialization ────────────────────────────────────────

audit_logger = AuditLogger(
    secret_key=settings.HMAC_SECRET,
    log_level=settings.LOG_LEVEL,
)

rate_limiter = RateLimiter(
    requests_per_minute=settings.RATE_LIMIT_PER_MINUTE,
)

input_validator = InputValidator()

logger = logging.getLogger("cobalto.api")

# ── Authentication ──────────────────────────────────────────────────

if settings.COBALTO_API_KEY or settings.COBALTO_API_KEYS:
    app.add_middleware(AuthMiddleware)
    logger.info("API authentication enabled")
elif not settings.COBALTO_DISABLE_AUTH:
    logger.warning(
        "No COBALTO_API_KEY configured. Authentication is DISABLED. "
        "Set COBALTO_API_KEY for production."
    )


# ── Models ──────────────────────────────────────────────────────────

class AgentResult(BaseModel):
    """Response model for alert analysis results."""
    incident_id: str
    final_report: str
    severity: str
    response_actions: list[dict]
    human_approved: bool
    approval_timeout: bool
    messages: list[str]


# ── Middleware: Request Timing & Audit ──────────────────────────────

@app.middleware("http")
async def audit_and_metrics_middleware(request: Request, call_next):
    """Log all requests, track duration, apply rate limits."""

    start_time = time.monotonic()

    # Apply rate limiting on non-health endpoints
    if request.url.path not in ("/health", "/ready", "/metrics"):
        agent_id = request.headers.get("X-Agent-Id", "anonymous")
        if not rate_limiter.allow(agent_id):
            audit_logger.log_error(
                agent_id=agent_id,
                error="rate_limit_exceeded",
                context={"path": request.url.path, "agent_id": agent_id},
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests. Rate limit exceeded.",
                    "retry_after_seconds": 60,
                },
            )

    # Process request
    response = await call_next(request)

    # Log audit entry for analysis requests
    if request.url.path == "/agent/analyze":
        duration_ms = (time.monotonic() - start_time) * 1000
        audit_logger.log_action(
            agent_id=request.headers.get("X-Agent-Id", "api"),
            action="request_completed",
            details={
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            },
            severity="INFO" if response.status_code < 400 else "ERROR",
        )

    return response


# ── API Endpoints ───────────────────────────────────────────────────

@app.post("/agent/analyze", response_model=AgentResult)
async def analyze_alert(payload: AlertPayload):
    """
    Analyze a security alert through the multi-agent pipeline.

    The alert goes through: triage → analysis → threat intel → response → human approval → documentation.
    Returns a comprehensive incident report with response actions.
    """
    config = {"configurable": {"thread_id": str(uuid.uuid4())}}

    # ── Input Validation ──
    try:
        input_validator.reject_malformed(dict(payload))
    except ValueError as e:
        audit_logger.log_error(
            agent_id="input_validator",
            error="validation_failed",
            context={"alert_id": payload.get("alert_id", "unknown"), "error": str(e)},
        )
        raise HTTPException(status_code=422, detail=str(e))

    # ── Audit: Alert Received ──
    audit_logger.log_alert_received(
        alert_id=payload.get("alert_id", "unknown"),
        alert_data={
            "rule_id": payload.get("rule_id"),
            "alert_level": payload.get("alert_level"),
            "agent_name": payload.get("agent_name"),
            "source_ip": payload.get("source_ip"),
        },
    )

    # ── Build Initial State ──
    initial_state = {
        "alert": dict(payload),
        "severity": "",
        "false_positive_probability": 0.0,
        "mitre_techniques": [],
        "attack_narrative": "",
        "affected_assets": [],
        "threat_actor_matches": [],
        "ioc_enrichment": {},
        "response_actions": [],
        "human_approved": False,
        "approval_timeout": False,
        "incident_id": "",
        "final_report": "",
        "messages": [],
    }

    # ── Execute Agent Pipeline ──
    try:
        # Log agent start
        audit_logger.log_agent_start("triage_agent", payload.get("alert_id", "unknown"))

        final_state = await agent.ainvoke(initial_state, config)

        # Log agent completion
        audit_logger.log_agent_complete(
            "orchestrator",
            payload.get("alert_id", "unknown"),
            {
                "severity": final_state.get("severity", ""),
                "incident_id": final_state.get("incident_id", ""),
                "response_count": len(final_state.get("response_actions", [])),
                "human_approved": final_state.get("human_approved", False),
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        audit_logger.log_error(
            agent_id="orchestrator",
            error="agent_pipeline_failed",
            context={
                "alert_id": payload.get("alert_id", "unknown"),
                "error": str(e),
            },
        )
        raise HTTPException(status_code=500, detail=str(e))

    return AgentResult(
        incident_id=final_state.get("incident_id", ""),
        final_report=final_state.get("final_report", ""),
        severity=final_state.get("severity", ""),
        response_actions=final_state.get("response_actions", []),
        human_approved=final_state.get("human_approved", False),
        approval_timeout=final_state.get("approval_timeout", False),
        messages=final_state.get("messages", []),
    )


@app.get("/health")
async def health_check():
    """Liveness probe — returns 200 if the service is alive."""
    return {"status": "healthy", "service": "langgraph-agent"}


@app.get("/ready")
async def readiness_check():
    """Readiness probe — returns 200 if the service is ready to accept traffic."""
    return {"status": "ready", "service": "langgraph-agent"}


@app.get("/metrics")
async def metrics():
    """
    Prometheus metrics endpoint.
    Returns basic application metrics in Prometheus text format.
    """
    from prometheus_client import generate_latest, REGISTRY, Counter, Histogram

    # Ensure metrics are registered
    if not hasattr(app, "_metrics_registered"):
        REQUEST_COUNT = Counter(
            "cobalto_requests_total",
            "Total request count",
            ["method", "endpoint", "status"],
        )
        REQUEST_LATENCY = Histogram(
            "cobalto_request_latency_seconds",
            "Request latency in seconds",
            ["endpoint"],
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
        )
        app.state.REQUEST_COUNT = REQUEST_COUNT
        app.state.REQUEST_LATENCY = REQUEST_LATENCY
        app._metrics_registered = True

    return Response(
        content=generate_latest(REGISTRY).decode("utf-8"),
        media_type="text/plain; version=0.0.4",
    )


@app.get("/graph/visualize")
async def visualize_graph():
    """Return the agent workflow graph as a Mermaid diagram."""
    mermaid = agent.get_graph().draw_mermaid()
    return {"mermaid": mermaid}
