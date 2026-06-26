import uuid
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from state import AlertPayload
from graph import agent


app = FastAPI(title="Cobalto SOC LangGraph Agent", version="1.0.0")


class AgentResult(BaseModel):
    incident_id: str
    final_report: str
    severity: str
    response_actions: list[dict]
    human_approved: bool
    approval_timeout: bool
    messages: list[str]


@app.post("/agent/analyze", response_model=AgentResult)
async def analyze_alert(payload: AlertPayload):
    config = {"configurable": {"thread_id": str(uuid.uuid4())}}

    initial_state = {
        "alert": payload,
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

    try:
        final_state = await agent.ainvoke(initial_state, config)
    except Exception as e:
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
    return {"status": "healthy", "service": "langgraph-agent"}


@app.get("/ready")
async def readiness_check():
    return {"status": "ready", "service": "langgraph-agent"}


@app.get("/graph/visualize")
async def visualize_graph():
    mermaid = agent.get_graph().draw_mermaid()
    return {"mermaid": mermaid}
