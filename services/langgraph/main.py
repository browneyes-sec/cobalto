"""
LangGraph Agent Service
Main FastAPI application for agent orchestration with MCP Bridge.
"""

import time
import asyncio
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
import uuid

from cobalto.core.config import get_settings
from cobalto.core.logging import setup_logging, get_logger
from cobalto.core.metrics import Metrics, record_http_request
from cobalto.core.health import HealthChecker, HealthStatus
from cobalto.agent.supervisor import SupervisorAgent
from cobalto.agent.base_agent import AgentConfig, AgentType

# Phase 2: Agent Registry + Context injection
from cobalto.agent.registry import (
    AgentRegistry,
    AgentCapability,
    get_agent_registry,
)
from cobalto.agent.tool_registry import (
    UnifiedToolRegistry,
    ToolDefinition,
    ToolRiskLevel,
    get_tool_registry as get_unified_tool_registry,
)
from cobalto.agent.base_agent import BaseAgent
from cobalto.context.ports import create_context_provider

# MCP imports
from cobalto.mcp.server import MCPServer
from cobalto.mcp.registry.tools import get_tool_registry
from cobalto.mcp.registry.resources import get_resource_registry
from cobalto.mcp.registry.prompts import get_prompt_registry

# SOAR SDK — SIEM alert normalization (extracted from inline models)
from cobalto.soar.webhook_models import WazuhAlert, N8NWebhookPayload
from cobalto.soar.webhook_wazuh import normalize_wazuh_alert, build_alert_context

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

    # ── Initialize core components ───────────────────────────────
    app.state.metrics = Metrics("langgraph-api")
    app.state.health_checker = HealthChecker("langgraph-api")

    # ── Phase 2: Wire AgentRegistry + Context injection ──────────

    # 1. Create context provider from settings
    context_provider = create_context_provider(
        qdrant_url=settings.qdrant_url,
        redis_url=settings.redis_url,
        opencti_url=settings.opencti_url,
        opencti_token=settings.opencti_token,
        max_context_tokens=8000,
    )

    # 2. Create Silver agents with context injection
    from services.langgraph.agents.triage import SilverTriageAgent
    from services.langgraph.agents.analysis import SilverAnalysisAgent
    from services.langgraph.agents.response import SilverResponseAgent
    from services.langgraph.agents.threat_intel import ThreatIntelAgent

    triage_agent = SilverTriageAgent(context_builder=context_provider)
    analysis_agent = SilverAnalysisAgent(context_builder=context_provider)
    response_agent = SilverResponseAgent(context_builder=context_provider)
    threat_intel_agent = ThreatIntelAgent()

    # 3. Register agents in AgentRegistry
    agent_registry = get_agent_registry()
    agent_registry.register(triage_agent)
    agent_registry.register(analysis_agent)
    agent_registry.register(response_agent)
    agent_registry.register(threat_intel_agent)

    logger.info("agents_registered", count=agent_registry.count())

    # 4. Create supervisor with registry attached
    app.state.supervisor = SupervisorAgent(agent_registry=agent_registry)
    app.state.agent_registry = agent_registry

    # 5. Store agents for route handlers
    app.state.agents = {
        "triage": triage_agent,
        "analysis": analysis_agent,
        "response": response_agent,
        "threat_intel": threat_intel_agent,
    }

    # ── Phase 3: Unified Tool Registry + MCP Bridge ─────────────
    from cobalto.mcp.registry.sync import sync_mcp_tools_to_unified

    # 1. Import MCP tool modules (triggers @mcp_tool decorators on legacy registry)
    _register_mcp_tools()
    _register_mcp_resources()
    _register_mcp_prompts()

    # 2. Sync legacy MCP tools into the single source of truth
    synced_count = sync_mcp_tools_to_unified(unified_registry=get_unified_tool_registry())
    logger.info("unified_tool_registry_synced", tool_count=synced_count)

    # 3. Initialize MCP Server with the unified tool registry
    app.state.mcp_server = MCPServer(
        name="cobalto-langgraph-mcp",
        version="0.1.0",
        unified_tool_registry=unified_registry,
    )

    # SSE session storage
    app.state.mcp_sessions: Dict[str, asyncio.Queue] = {}

    logger.info(
        "langgraph_service_started",
        mcp_enabled=settings.mcp_server_enabled,
        agent_count=agent_registry.count(),
        context_provider="context_provider",
    )

    yield

    logger.info("langgraph_service_shutting_down")


def _register_mcp_tools():
    """Register all MCP tools."""
    from cobalto.mcp.tools import wazuh, opencti, thehive, response
    logger.info("mcp_tools_registered")


def _register_mcp_resources():
    """Register all MCP resources."""
    from cobalto.mcp.resources import soc_resources
    logger.info("mcp_resources_registered")


def _register_mcp_prompts():
    """Register all MCP prompts."""
    from cobalto.mcp.prompts import soc_prompts
    logger.info("mcp_prompts_registered")


# Create FastAPI app
app = FastAPI(
    title="Cobalto LangGraph Agent Service",
    description="Multi-agent AI orchestration for threat detection and response",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS - use configurable allowed origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


# Middleware for correlation ID
@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """Inject correlation ID into logs and responses."""
    import structlog

    correlation_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    structlog.contextvars.bind_contextvars(correlation_id=correlation_id)
    request.state.correlation_id = correlation_id

    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = correlation_id
        return response
    finally:
        structlog.contextvars.unbind_contextvars("correlation_id")


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
    """Run a specific agent using the AgentRegistry."""
    start_time = time.time()

    try:
        from cobalto.agent.base_agent import AgentType

        # Find agent by type in the registry
        agent_type = AgentType(request.agent_type)
        agents = app.state.agent_registry.find_agents_by_type(agent_type)

        if not agents:
            logger.warning("agent_not_found", agent_type=request.agent_type)
            # Fallback: try pre-created agents
            agent = app.state.agents.get(request.agent_type)
            if agent is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"No agent found for type: {request.agent_type}",
                )
        else:
            agent = agents[0]

        result = await agent.run({
            **request.input_data,
            "context": request.context or {},
        })

        duration_ms = (time.time() - start_time) * 1000

        return AgentResponse(
            agent_id=agent.agent_id,
            agent_type=request.agent_type,
            status="success",
            output=result.output,
            duration_ms=duration_ms,
        )

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid agent type: {str(e)}")
    except Exception as e:
        logger.exception("run_agent_failed", agent_type=request.agent_type, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/triage")
async def triage_alert(request: AnalyzeRequest):
    """Triage an alert using pre-created agent with context injection."""
    start_time = time.time()

    try:
        agent = app.state.agents.get("triage")
        if agent is None:
            raise HTTPException(status_code=503, detail="Triage agent not available")

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

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("triage_alert_failed", alert_id=request.alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/analyze-deep")
async def analyze_deep(request: AnalyzeRequest):
    """Deep analysis of an alert using pre-created agent with context injection."""
    start_time = time.time()

    try:
        agent = app.state.agents.get("analysis")
        if agent is None:
            raise HTTPException(status_code=503, detail="Analysis agent not available")

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

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("analyze_deep_failed", alert_id=request.alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/threat-intel")
async def threat_intel_lookup(request: AnalyzeRequest):
    """Threat intelligence lookup using pre-created agent."""
    start_time = time.time()

    try:
        agent = app.state.agents.get("threat_intel")
        if agent is None:
            raise HTTPException(status_code=503, detail="Threat intel agent not available")

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

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("threat_intel_failed", alert_id=request.alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/agent/response")
async def generate_response(request: AnalyzeRequest):
    """Generate response actions using pre-created agent with context injection."""
    start_time = time.time()

    try:
        agent = app.state.agents.get("response")
        if agent is None:
            raise HTTPException(status_code=503, detail="Response agent not available")

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

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("generate_response_failed", alert_id=request.alert_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Webhook Endpoints for Alert Ingestion
# =============================================================================

@app.post("/webhook/wazuh")
async def wazuh_webhook(payload: N8NWebhookPayload):
    """
    Receive alerts from Wazuh via n8n webhook.
    
    Flow: Wazuh → n8n → Cobalt (this endpoint) → Supervisor → Silver Agents
    
    Normalization logic is delegated to :func:`cobalto.soar.webhook_wazuh.normalize_wazuh_alert`
    so it can be unit-tested independently of the FastAPI routing layer.
    """
    start_time = time.time()
    
    try:
        alert_id = payload.alert_id
        logger.info(
            "wazuh_alert_received",
            alert_id=alert_id,
            rule_id=payload.alert.rule_id,
            rule_level=payload.alert.rule_level,
            agent_id=payload.alert.agent_id,
            tenant_id=payload.tenant_id,
        )
        
        # Delegate normalization to SOAR SDK
        normalized_alert = normalize_wazuh_alert(payload)
        context = build_alert_context(payload)
        
        # Run supervisor analysis
        supervisor = app.state.supervisor
        result = await supervisor.run({
            "alert_id": alert_id,
            "alert": normalized_alert,
            "context": context,
        })
        
        duration_ms = (time.time() - start_time) * 1000
        
        logger.info(
            "wazuh_alert_processed",
            alert_id=alert_id,
            duration_ms=duration_ms,
            status=result.output.get("status", "unknown"),
        )
        
        return JSONResponse(
            status_code=200,
            content={
                "alert_id": alert_id,
                "status": "processed",
                "routing": result.output.get("routing", {}),
                "duration_ms": duration_ms,
            },
        )
        
    except Exception as e:
        logger.exception(
            "wazuh_webhook_failed",
            alert_id=payload.alert_id if payload else "unknown",
            error=str(e),
        )
        return JSONResponse(
            status_code=500,
            content={
                "alert_id": payload.alert_id if payload else "unknown",
                "status": "error",
                "error": str(e),
            },
        )


@app.post("/webhook/generic")
async def generic_webhook(request: Request):
    """
    Generic webhook receiver for other SIEM/EDR integrations.
    
    Accepts any JSON payload and routes through the supervisor.
    """
    start_time = time.time()
    
    try:
        body = await request.json()
        
        # Extract or generate alert_id
        alert_id = body.get("alert_id") or body.get("id") or f"generic-{uuid.uuid4().hex[:12]}"
        
        logger.info("generic_alert_received", alert_id=alert_id)
        
        # Run supervisor analysis
        supervisor = app.state.supervisor
        result = await supervisor.run({
            "alert_id": alert_id,
            "alert": body,
            "context": {
                "tenant_id": "default",
                "source": "generic_webhook",
            },
        })
        
        duration_ms = (time.time() - start_time) * 1000
        
        return JSONResponse(
            status_code=200,
            content={
                "alert_id": alert_id,
                "status": "processed",
                "routing": result.output.get("routing", {}),
                "duration_ms": duration_ms,
            },
        )
        
    except Exception as e:
        logger.exception("generic_webhook_failed", error=str(e))
        return JSONResponse(
            status_code=500,
            content={"status": "error", "error": str(e)},
        )


@app.post("/webhook/n8n")
async def n8n_callback(request: Request):
    """
    Callback endpoint for n8n workflows.
    
    n8n can call this endpoint to trigger agent actions or get results.
    """
    start_time = time.time()
    
    try:
        body = await request.json()
        action = body.get("action")
        data = body.get("data", {})
        
        logger.info("n8n_callback_received", action=action)
        
        if action == "triage":
            result = await app.state.supervisor.run({
                "alert_id": data.get("alert_id", f"n8n-{uuid.uuid4().hex[:8]}"),
                "alert": data.get("alert", {}),
                "context": data.get("context", {}),
            })
        else:
            return JSONResponse(
                status_code=400,
                content={"error": f"Unknown action: {action}"},
            )
        
        duration_ms = (time.time() - start_time) * 1000
        
        return JSONResponse(
            status_code=200,
            content={
                "status": "success",
                "result": result.output,
                "duration_ms": duration_ms,
            },
        )
        
    except Exception as e:
        logger.exception("n8n_callback_failed", error=str(e))
        return JSONResponse(
            status_code=500,
            content={"status": "error", "error": str(e)},
        )


# =============================================================================
# MCP Bridge Endpoints
# =============================================================================

@app.get("/mcp")
async def mcp_info():
    """MCP server information."""
    mcp_server = app.state.mcp_server
    return JSONResponse(content=mcp_server.get_server_info())


@app.get("/mcp/sse")
async def mcp_sse():
    """SSE endpoint for MCP protocol."""
    if not settings.mcp_server_enabled:
        raise HTTPException(status_code=503, detail="MCP server disabled")

    session_id = f"session-{uuid.uuid4().hex[:8]}"
    queue: asyncio.Queue = asyncio.Queue()
    app.state.mcp_sessions[session_id] = queue

    async def event_generator():
        try:
            # Send connection event
            yield f"event: connected\ndata: {json.dumps({'session_id': session_id})}\n\n"

            while True:
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=30)
                    if message is None:
                        break
                    yield f"data: {json.dumps(message)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            app.state.mcp_sessions.pop(session_id, None)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/mcp/messages")
async def mcp_messages(request: Request):
    """Handle MCP JSON-RPC messages."""
    if not settings.mcp_server_enabled:
        raise HTTPException(status_code=503, detail="MCP server disabled")

    try:
        body = await request.json()
        session_id = request.query_params.get("session_id")

        mcp_server = app.state.mcp_server
        response = await mcp_server.handle_message(body)

        # Send to SSE stream if session exists
        if session_id and session_id in app.state.mcp_sessions:
            if response:
                await app.state.mcp_sessions[session_id].put(json.loads(response))

        return JSONResponse(
            content=json.loads(response) if response else {"ok": True},
        )

    except Exception as e:
        logger.exception("mcp_message_error", error=str(e))
        return JSONResponse(
            status_code=500,
            content={
                "jsonrpc": "2.0",
                "error": {"code": -32603, "message": str(e)},
                "id": None,
            },
        )


@app.get("/mcp/tools")
async def mcp_list_tools():
    """List available MCP tools."""
    tool_registry = get_tool_registry()
    tools = tool_registry.list_tools()
    return JSONResponse(
        content={"tools": [tool.model_dump() for tool in tools]}
    )


@app.get("/mcp/resources")
async def mcp_list_resources():
    """List available MCP resources."""
    resource_registry = get_resource_registry()
    resources = resource_registry.list_resources()
    templates = resource_registry.list_templates()
    return JSONResponse(
        content={
            "resources": [r.model_dump() for r in resources],
            "templates": [t.model_dump() for t in templates],
        }
    )


@app.get("/mcp/prompts")
async def mcp_list_prompts():
    """List available MCP prompts."""
    prompt_registry = get_prompt_registry()
    prompts = prompt_registry.list_prompts()
    return JSONResponse(
        content={"prompts": [p.model_dump() for p in prompts]}
    )


@app.post("/mcp/tools/{tool_name}/call")
async def mcp_call_tool(tool_name: str, request: Request):
    """Call an MCP tool directly via HTTP."""
    if not settings.mcp_server_enabled:
        raise HTTPException(status_code=503, detail="MCP server disabled")

    try:
        body = await request.json()
        arguments = body.get("arguments", {})

        tool_registry = get_tool_registry()
        result = await tool_registry.call_tool(tool_name, arguments)

        return JSONResponse(content=result.model_dump())

    except Exception as e:
        logger.exception("mcp_tool_call_error", tool=tool_name, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/mcp/health")
async def mcp_health():
    """MCP health check."""
    tool_registry = get_tool_registry()
    resource_registry = get_resource_registry()
    prompt_registry = get_prompt_registry()

    return JSONResponse(
        content={
            "status": "healthy",
            "tools_count": len(tool_registry.list_tool_names()),
            "resources_count": len(resource_registry.list_uris()),
            "prompts_count": len(prompt_registry.list_prompt_names()),
            "sessions_count": len(app.state.mcp_sessions) if hasattr(app.state, 'mcp_sessions') else 0,
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)