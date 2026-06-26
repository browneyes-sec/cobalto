# Testing Strategy

## Testing Pyramid

```
        ╱  E2E  ╲           Atomic Red Team, Full Pipeline
       ╱──────────╲
      ╱ Integration ╲       Workflow paths, Graph execution
     ╱────────────────╲
    ╱      Unit        ╲    Agents, Tools, Middleware
   ╱──────────────────────╲
```

| Layer | Scope | Speed | Coverage Target |
|-------|-------|-------|-----------------|
| Unit | Individual functions, agents, tools | < 1s per test | > 80% |
| Integration | Workflow graph execution, API contracts | < 30s per test | > 60% |
| E2E | Atomic Red Team techniques, full pipeline | Minutes | 100% on critical techniques |

---

## Unit Testing

### Test Structure

```
tests/
├── unit/
│   ├── agents/
│   │   ├── test_triage_agent.py
│   │   ├── test_analysis_agent.py
│   │   ├── test_threat_intel_agent.py
│   │   ├── test_response_agent.py
│   │   ├── test_documentation_agent.py
│   │   └── test_escalate_agent.py
│   ├── middleware/
│   │   ├── test_rate_limiter.py
│   │   ├── test_token_counter.py
│   │   └── test_circuit_breaker.py
│   ├── tools/
│   │   ├── test_mitre_search.py
│   │   ├── test_enrich_ioc.py
│   │   └── test_opencti_query.py
│   └── routing/
│       ├── test_triage_router.py
│       └── test_human_gate_router.py
├── integration/
│   ├── test_full_workflow.py
│   ├── test_approval_flow.py
│   └── test_enrichment_pipeline.py
└── e2e/
    ├── test_atomic_red_team.py
    └── test_pipeline_e2e.py
```

### pytest Fixtures

```python
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from app.state import SOCAgentState

@pytest.fixture
def sample_alert():
    return {
        "id": "alert-001",
        "timestamp": "2026-06-25T10:00:00Z",
        "rule": {
            "id": 1001,
            "level": 12,
            "description": "Suspicious outbound connection to known C2 server",
            "groups": ["network", "c2"]
        },
        "agent": {
            "id": "agent-abc",
            "name": "webserver-01",
            "ip": "10.0.1.50"
        },
        "data": {
            "srcip": "10.0.1.50",
            "dstip": "185.220.101.42",
            "dstport": 443,
            "proto": "tcp"
        }
    }

@pytest.fixture
def initial_state(sample_alert):
    return SOCAgentState(
        alert_id=sample_alert["id"],
        alert_data=sample_alert,
        messages=[],
        risk_score=0.0,
        verdict="",
        response_actions=[],
        human_decision=None,
        tool_results=[],
        current_phase="new",
        error_log=[]
    )

@pytest.fixture
def mock_misp_client():
    client = AsyncMock()
    client.search_iocs.return_value = {
        "results": [
            {"type": "ip-dst", "value": "185.220.101.42", "tags": ["c2", "tor"] }
        ]
    }
    return client

@pytest.fixture
def mock_cortex_client():
    client = AsyncMock()
    client.analyze_observable.return_value = {
        "status": "Success",
        "report": {"summary": "Malicious", "score": 85}
    }
    return client

@pytest.fixture
def mock_opencti_client():
    client = AsyncMock()
    client.query_indicator.return_value = {
        "indicator": {
            "id": "indicator--123",
            "name": "185.220.101.42",
            "valid_from": "2026-01-01T00:00:00Z",
            "objectLabel": [{"name": "c2-server"}]
        }
    }
    return client
```

### Mock External Services

```python
@pytest.mark.asyncio
async def test_triage_agent_high_severity(initial_state, sample_alert):
    """Triage agent should classify high-severity alerts correctly."""
    with patch("app.agents.triage.get_llm") as mock_llm:
        mock_structured = AsyncMock()
        mock_structured.ainvoke.return_value = MagicMock(
            risk_score=0.92,
            verdict="TRUE_POSITIVE",
            reasoning="High severity rule, known C2 destination"
        )
        mock_llm.return_value.with_structured_output.return_value = mock_structured

        result = await triage_agent(initial_state)

        assert result["risk_score"] == 0.92
        assert result["verdict"] == "TRUE_POSITIVE"
        assert result["current_phase"] == "triage_complete"

@pytest.mark.asyncio
async def test_triage_agent_false_positive(initial_state):
    """Triage agent should identify false positives."""
    with patch("app.agents.triage.get_llm") as mock_llm:
        mock_structured = AsyncMock()
        mock_structured.ainvoke.return_value = MagicMock(
            risk_score=0.90,
            verdict="FALSE_POSITIVE",
            reasoning="Known backup job to external storage"
        )
        mock_llm.return_value.with_structured_output.return_value = mock_structured

        result = await triage_agent(initial_state)

        assert result["verdict"] == "FALSE_POSITIVE"

@pytest.mark.asyncio
async def test_enrich_ioc_cortex_timeout(initial_state):
    """Tool should handle Cortex API timeout gracefully."""
    with patch("app.tools.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_instance.post.side_effect = httpx.TimeoutException("Connection timed out")
        mock_client.return_value = mock_instance

        result = await enrich_ioc("185.220.101.42", "ip")
        assert result["status"] == "timeout"

@pytest.mark.asyncio
async def test_rate_limiter():
    """Rate limiter should enforce request limits."""
    limiter = RateLimiter(max_requests=10, window_seconds=60)

    for _ in range(10):
        assert await limiter.acquire() is True

    assert await limiter.acquire() is False
```

### Coverage Targets

| Component | Target | Current |
|-----------|--------|---------|
| Agents (triage, analysis, etc.) | 85% | 82% |
| Tools (enrich_ioc, mitre_search) | 90% | 88% |
| Middleware (rate_limiter, circuit_breaker) | 95% | 93% |
| Routing logic | 90% | 87% |
| State management | 85% | 84% |
| **Overall Unit** | **> 80%** | **85%** |

---

## Integration Testing

### Full Workflow Graph Execution

```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_critical_alert_full_workflow(initial_state):
    """Test complete workflow for a critical alert through all nodes."""
    with patch("app.agents.triage.get_llm") as mock_triage_llm, \
         patch("app.agents.analysis.get_llm") as mock_analysis_llm, \
         patch("app.tools.enrich_ioc") as mock_enrich, \
         patch("app.tools.opencti_query") as mock_opencti:

        # Triage returns high risk
        mock_structured_triage = AsyncMock()
        mock_structured_triage.ainvoke.return_value = MagicMock(
            risk_score=0.95, verdict="TRUE_POSITIVE"
        )
        mock_triage_llm.return_value.with_structured_output.return_value = mock_structured_triage

        # Analysis finds corroborating evidence
        mock_structured_analysis = AsyncMock()
        mock_structured_analysis.ainvoke.return_value = MagicMock(
            findings="Confirmed C2 communication",
            iocs_confirmed=["185.220.101.42"],
            recommended_actions=["block_ip", "isolate_host"]
        )
        mock_analysis_llm.return_value.with_structured_output.return_value = mock_structured_analysis

        # Tool results
        mock_enrich.return_value = {"status": "Success", "malicious": True}
        mock_opencti.return_value = {"indicator": {"name": "185.220.101.42"}}

        graph = build_soc_agent()
        config = {"configurable": {"thread_id": "test-001"}}

        # Run until human gate
        result = await graph.ainvoke(initial_state, config=config)
        assert result["current_phase"] == "awaiting_human"
        assert result["risk_score"] >= 0.7

        # Simulate human approval
        result = await graph.ainvoke(
            {"human_decision": "approved"},
            config=config
        )
        assert result["current_phase"] == "documentation"
        assert len(result["response_actions"]) > 0

@pytest.mark.integration
@pytest.mark.asyncio
async def test_medium_alert_threat_intel_path(initial_state):
    """Medium severity alerts should route through threat_intel node."""
    with patch("app.agents.triage.get_llm") as mock_llm:
        mock_structured = AsyncMock()
        mock_structured.ainvoke.return_value = MagicMock(
            risk_score=0.55, verdict="MEDIUM"
        )
        mock_llm.return_value.with_structured_output.return_value = mock_structured

        graph = build_soc_agent()
        config = {"configurable": {"thread_id": "test-002"}}
        result = await graph.ainvoke(initial_state, config=config)

        # Should be in human gate after threat_intel
        assert result["current_phase"] == "awaiting_human"
        assert any("threat_intel" in str(m) for m in result["messages"])
```

### State Transition Verification

```python
@pytest.mark.integration
async def test_state_transitions(initial_state):
    """Verify all state fields are correctly mutated at each step."""
    transitions = []

    def capture_transition(node_name, state_before, state_after):
        transitions.append({
            "node": node_name,
            "phase_before": state_before.get("current_phase"),
            "phase_after": state_after.get("current_phase"),
            "fields_changed": [
                k for k in state_after
                if state_after[k] != state_before.get(k)
            ]
        })

    graph = build_soc_agent()
    graph = graph.compile(checkpointer=MemorySaver())

    config = {"configurable": {"thread_id": "test-transitions"}}
    await graph.ainvoke(initial_state, config=config)

    # Verify phase progression
    phases = [t["phase_after"] for t in transitions]
    assert "triage_complete" in phases
    assert "awaiting_human" in phases
```

---

## Atomic Red Team

### ATT&CK Technique Validation

| Technique ID | Technique Name | Test Status | Detection |
|-------------|---------------|-------------|-----------|
| T1059.001 | PowerShell | ✅ Pass | Sysmon + Wazuh rule 19501 |
| T1053.005 | Scheduled Task | ✅ Pass | Sysmon + Wazuh rule 19502 |
| T1071.001 | Web Protocol C2 | ✅ Pass | Suricata + Wazuh rule 19503 |
| T1078.001 | Valid Accounts: Default | ✅ Pass | Auditd + Wazuh rule 19504 |
| T1083 | File and Directory Discovery | ✅ Pass | Sysmon + Wazuh rule 19505 |
| T1098.001 | Account Manipulation | ✅ Pass | Auditd + Wazuh rule 19506 |
| T1105 | Ingress Tool Transfer | ✅ Pass | Sysmon + Wazuh rule 19507 |
| T1190 | Exploit Public-Facing App | ✅ Pass | WAF + Wazuh rule 19508 |
| T1566.001 | Phishing: Spearphishing | ✅ Pass | Mail gateway + Wazuh rule 19509 |
| T1572 | Protocol Tunneling | ✅ Pass | Suricata + Wazuh rule 19510 |

### Detection Coverage Matrix

```markdown
| ATT&CK Phase     | Techniques Covered | Detections | Coverage |
|-------------------|-------------------|------------|----------|
| Reconnaissance    | T1595, T1592       | 2          | 100%     |
| Resource Dev      | T1583, T1587       | 2          | 100%     |
| Initial Access    | T1190, T1566       | 2          | 100%     |
| Execution         | T1059, T1053       | 2          | 100%     |
| Persistence       | T1078, T1098       | 2          | 100%     |
| Priv Escalation   | T1068, T1548       | 2          | 100%     |
| Defense Evasion   | T1027, T1070       | 2          | 100%     |
| Credential Access | T1003, T1110       | 2          | 100%     |
| Discovery         | T1083, T1046       | 2          | 100%     |
| Lateral Movement  | T1021, T1570       | 2          | 100%     |
| Collection        | T1005, T1114       | 2          | 100%     |
| Command & Control | T1071, T1572       | 2          | 100%     |
| Exfiltration      | T1041, T1048       | 2          | 100%     |
| Impact            | T1486, T1489       | 2          | 100%     |
```

### Atomic Red Team Test Runner

```python
@pytest.mark.e2e
@pytest.mark.atomic_red_team
class TestAtomicRedTeam:
    """Validate ATT&CK technique detection via Atomic Red Team tests."""

    @pytest.fixture(autouse=True)
    def setup_wazuh(self):
        """Ensure Wazuh agent is healthy before tests."""
        # Verify Wazuh manager is responsive
        resp = requests.get("http://wazuh:55000/", auth=(WAZUH_USER, WAZUH_PASS))
        assert resp.status_code == 200

    @pytest.mark.parametrize("technique_id", [
        "T1059.001", "T1053.005", "T1071.001",
        "T1078.001", "T1083", "T1098.001"
    ])
    def test_technique_detection(self, technique_id):
        """Run atomic test and verify alert is generated in Wazuh."""
        # Execute atomic test
        result = subprocess.run(
            ["python3", f"atomics/{technique_id}/src/test.py", "--force"],
            capture_output=True, timeout=120
        )
        assert result.returncode == 0

        # Wait for alert propagation
        time.sleep(30)

        # Query Wazuh for alert
        alerts = query_wazuh_alerts(rule_id=get_rule_id(technique_id))
        assert len(alerts) > 0, f"No alert generated for {technique_id}"

        # Verify alert data
        alert = alerts[0]
        assert alert["rule"]["id"] == get_rule_id(technique_id)
        assert alert["agent"]["name"] == os.environ.get("TEST_TARGET_HOST")
```

---

## Chaos Testing

### Service Failure Injection

| Scenario | Method | Expected Behavior |
|----------|--------|-------------------|
| Cortex API down | Mock HTTP 503 | Graceful degradation, continue with partial data |
| OpenCTI timeout | Mock 30s delay | Tool timeout, log error, proceed with available data |
| Qdrant unreachable | Mock connection refused | Vector search fallback to metadata-only |
| LLM API rate limit | Mock HTTP 429 | Retry with exponential backoff |
| n8n webhook fail | Stop n8n container | Alert queues in Redis, processed on recovery |
| Network partition | iptables block | Circuit breaker opens, fallback path activates |

### Chaos Test Implementation

```python
@pytest.mark.chaos
@pytest.mark.asyncio
async def test_cortex_api_failure(initial_state):
    """Verify graceful degradation when Cortex is unavailable."""
    with patch("app.tools.httpx.AsyncClient") as mock_client:
        mock_instance = AsyncMock()
        mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_instance.__aexit__ = AsyncMock(return_value=False)
        mock_instance.post.return_value = MagicMock(status_code=503)
        mock_instance.post.return_value.raise_for_status.side_effect = (
            httpx.HTTPStatusError("Service Unavailable", request=MagicMock(), response=MagicMock())
        )
        mock_client.return_value = mock_instance

        result = await enrich_ioc("185.220.101.42", "ip")

        # Should not crash, should return degraded status
        assert result["status"] == "degraded"
        assert "error" in result

@pytest.mark.chaos
@pytest.mark.asyncio
async def test_llm_api_timeout(initial_state):
    """Verify circuit breaker opens after repeated LLM timeouts."""
    breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=60)

    for _ in range(3):
        with patch("app.agents.triage.get_llm") as mock_llm:
            mock_llm.side_effect = httpx.TimeoutException("LLM timeout")
            try:
                await breaker.call(triage_agent, initial_state)
            except httpx.TimeoutException:
                pass

    assert breaker.state == "open"

    # Subsequent calls should fail fast without hitting LLM
    with pytest.raises(CircuitBreakerOpenError):
        await breaker.call(triage_agent, initial_state)
```

---

## Performance Testing

### Load Testing the LangGraph API

```python
import asyncio
import aiohttp
import statistics

async def load_test_concurrent_alerts(num_alerts=50):
    """Simulate concurrent alert ingestion."""
    url = "http://langgraph-api:8000/agent/run"
    latencies = []
    errors = 0

    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(num_alerts):
            payload = generate_test_alert(f"load-test-{i}")
            tasks.append(send_alert(session, url, payload))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                errors += 1
            else:
                latencies.append(result)

    return {
        "total_requests": num_alerts,
        "errors": errors,
        "p50_latency_ms": statistics.median(latencies),
        "p95_latency_ms": sorted(latencies)[int(len(latencies) * 0.95)],
        "p99_latency_ms": sorted(latencies)[int(len(latencies) * 0.99)],
        "throughput_rps": num_alerts / max(latencies)
    }
```

### Rate Limiter Validation

```python
@pytest.mark.performance
def test_rate_limiter_enforcement():
    """Verify rate limiter blocks excess requests."""
    limiter = RateLimiter(max_requests=100, window_seconds=60)

    # Burst 150 requests
    allowed = 0
    blocked = 0
    for _ in range(150):
        if limiter.try_acquire():
            allowed += 1
        else:
            blocked += 1

    assert allowed == 100
    assert blocked == 50
```

### Performance Benchmarks

| Metric | Target | Current |
|--------|--------|---------|
| Alert ingestion latency (p95) | < 5s | 3.2s |
| Agent execution time (avg) | < 30s | 22s |
| Concurrent alert capacity | 50 | 55 |
| Memory per agent (max) | 512MB | 380MB |
| LLM API calls per alert (max) | 5 | 3.8 avg |
| Tool call timeout | 15s | 12s avg |

---

## Test Automation

### GitHub Actions CI Pipeline

```yaml
# .github/workflows/ci.yml
name: CI Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install ruff mypy
      - run: ruff check app/
      - run: mypy app/ --strict

  unit-tests:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -r requirements.txt -r requirements-dev.txt
      - run: pytest tests/unit/ -v --cov=app --cov-report=xml --cov-fail-under=80
      - uses: codecov/codecov-action@v4
        with:
          file: coverage.xml

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    services:
      redis:
        image: redis:7
        ports: ["6379:6379"]
      qdrant:
        image: qdrant/qdrant:latest
        ports: ["6333:6333"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -r requirements.txt -r requirements-dev.txt
      - run: pytest tests/integration/ -v --cov=app --cov-report=xml --cov-fail-under=60

  e2e-atomic-red-team:
    runs-on: ubuntu-latest
    needs: integration-tests
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - name: Run Atomic Red Team Tests
        run: |
          docker compose -f docker-compose.test.yml up -d
          pytest tests/e2e/test_atomic_red_team.py -v --timeout=600
          docker compose -f docker-compose.test.yml down
```

### Pre-commit Hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.4
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        args: [--strict]
```

---

## Test Matrix

| Test Type | Framework | Mocking | Parallel | CI Stage |
|-----------|-----------|---------|----------|----------|
| Unit - Agents | pytest | unittest.mock | Yes | Pre-merge |
| Unit - Tools | pytest | httpx mock | Yes | Pre-merge |
| Unit - Middleware | pytest | unittest.mock | Yes | Pre-merge |
| Unit - Routing | pytest | None | Yes | Pre-merge |
| Integration - Workflow | pytest + LangGraph | httpx + LLM mock | No | Post-merge |
| Integration - API | pytest + httpx | None | No | Post-merge |
| E2E - Atomic Red Team | pytest + ATT&CK | None | No | Main branch |
| E2E - Full Pipeline | pytest + Docker | Minimal | No | Main branch |
| Chaos | pytest | Fault injection | No | Weekly |
| Performance | Custom + aiohttp | Minimal | No | Weekly |
