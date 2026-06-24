"""
LangGraph Agent Service
Main FastAPI application for agent orchestration.
"""

import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
import uuid

from frameworks.core.config import get_settings
from frameworks.core.logging import setup_logging, get_logger
from frameworks.core.metrics import Metrics, record_http_request
from frameworks.core.health import HealthChecker, HealthStatus
from frameworks.agent.supervisor import SupervisorAgent
from frameworks.agent.base_agent import AgentConfig, AgentType

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Settings
settings = get_settings()

# Lifespan context
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan."""
    logger.info("langgraph_service_starting", env=settings.app_env)

    # Initialize components
    app.state.metrics = Metrics("langgraph-api")
    app.state.health_checker = HealthChecker("langgraph-api")
    app.state.supervisor = SupervisorAgent()

    yield

    logger.info("langgraph_service_shutting_down")


# Create FastAPI app
app = FastAPI(
    title="Cobalto LangGraph Agent Service",
    description="Multi-agent AI orchestration for threat detection and response",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Middleware for metrics
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """Track HTTP metrics."""
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    record_http_request(
        "langgraph-api",
        request.method,
        request.url.path,
        response.status_code,
        duration,
    )
    return response


# Request/Response models
class AnalyzeRequest(BaseModel):
    """Request for alert analysis."""
    alert_id: str
    alert: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


class AnalyzeResponse(BaseModel):
    """Response from alert analysis."""
    alert_id: str
    status: str
    routing: Dict[str, Any]
    duration_ms: float


class AgentRequest(BaseModel):
    """Request to run a specific agent."""
    agent_type: str
    input_data: Dict[str, Any]
    context: Optional[Dict[str, Any]] = None


class AgentResponse(BaseModel):
    """Response from agent execution."""
    agent_id: str
    agent_type: str
    status: str
    output: Dict[str, Any]
    duration_ms: float


# Routes
@app.get("/health")
async def health():
    """Health check endpoint."""
    checker = app.state.health_checker
    health_result = await checker.run_all_checks()

    status_code = 200
    if health_result.status == HealthStatus.DEGRADED:
        status_code = 200
    elif health_result.status == HealthStatus.UNHEALTHY:
        status_code = 503

    return JSONResponse(
        status_code=status_code,
        content=health_result.to_dict(),
    )


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    metrics_instance = app.state.metrics
    return JSONResponse(
        content=metrics_instance.get_metrics().decode("utf-8"),
        media_type="text/plain",
    )


@app.post("/agent/analyze", response_model=AnalyzeResponse)
async def analyze_alert(request: AnalyzeRequest):
    """Analyze an alert using the supervisor agent."""
    start_time = time.time()

    try:
        supervisor = app.state.supervisor
        result = await supervisor.run({
            "alert_id": request.alert_id,
            "alert": request.alert,
            "context": request.context or {},
        })

        duration_ms = (time.time() - start_time) * 1000

        return AnalyzeResponse(
            alert_id=request.alert_id,
            status="success",
            routing=result.output.get("routing", {}),
            duration_ms=duration_ms,
        )

    except Exception as e:
        logger.exception("analyze_alert_failed", alert_id=request.alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/run", response_model=AgentResponse)
async def run_agent(request: AgentRequest):
    """Run a specific agent."""
    start_time = time.time()

    try:
        # Import and instantiate the appropriate agent
        from frameworks.agent.base_agent import AgentType

        agent_type = AgentType(request.agent_type)

        # For now, return a placeholder
        # In production, this would instantiate and run the actual agent
        duration_ms = (time.time() - start_time) * 1000

        return AgentResponse(
            agent_id=f"{request.agent_type}-{uuid.uuid4().hex[:8]}",
            agent_type=request.agent_type,
            status="success",
            output={"message": f"Agent {request.agent_type} executed successfully"},
            duration_ms=duration_ms,
        )

    except Exception as e:
        logger.exception("run_agent_failed", agent_type=request.agent_type, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/triage")
async def triage_alert(request: AnalyzeRequest):
    """Triage an alert."""
    start_time = time.time()

    try:
        from services.langgraph.agents.triage import TriageAgent

        agent = TriageAgent()
        result = await agent.run({
            "alert_id": request.alert_id,
            "alert": request.alert,
            "context": request.context or {},
        })

        duration_ms = (time.time() - start_time) * 1000

        return {
            "alert_id": request.alert_id,
            "status": "success",
            "result": result.output,
            "duration_ms": duration_ms,
        }

    except Exception as e:
        logger.exception("triage_alert_failed", alert_id=request.alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/analyze-deep")
async def analyze_deep(request: AnalyzeRequest):
    """Deep analysis of an alert."""
    start_time = time.time()

    try:
        from services.langgraph.agents.analysis import AnalysisAgent

        agent = AnalysisAgent()
        result = await agent.run({
            "alert_id": request.alert_id,
            "alert": request.alert,
            "context": request.context or {},
        })

        duration_ms = (time.time() - start_time) * 1000

        return {
            "alert_id": request.alert_id,
            "status": "success",
            "result": result.output,
            "duration_ms": duration_ms,
        }

    except Exception as e:
        logger.exception("analyze_deep_failed", alert_id=request.alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/threat-intel")
async def threat_intel_lookup(request: AnalyzeRequest):
    """Threat intelligence lookup."""
    start_time = time.time()

    try:
        from services.langgraph.agents.threat_intel import ThreatIntelAgent

        agent = ThreatIntelAgent()
        result = await agent.run({
            "alert_id": request.alert_id,
            "alert": request.alert,
            "context": request.context or {},
        })

        duration_ms = (time.time() - start_time) * 1000

        return {
            "alert_id": request.alert_id,
            "status": "success",
            "result": result.output,
            "duration_ms": duration_ms,
        }

    except Exception as e:
        logger.exception("threat_intel_failed", alert_id=request.alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/response")
async def generate_response(request: AnalyzeRequest):
    """Generate response actions."""
    start_time = time.time()

    try:
        from services.langgraph.agents.response import ResponseAgent

        agent = ResponseAgent()
        result = await agent.run({
            "alert_id": request.alert_id,
            "alert": request.alert,
            "context": request.context or {},
        })

        duration_ms = (time.time() - start_time) * 1000

        return {
            "alert_id": request.alert_id,
            "status": "success",
            "result": result.output,
            "duration_ms": duration_ms,
        }

    except Exception as e:
        logger.exception("generate_response_failed", alert_id=request.alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)