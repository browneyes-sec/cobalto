import uuid

from state import SOCAgentState


async def triage_agent(state: SOCAgentState) -> dict:
    alert = state.get("alert", {})
    severity_map = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}
    alert_level = alert.get("alert_level", 1)
    severity = severity_map.get(alert_level, "LOW")

    fp_probability = 0.1 if alert_level <= 2 else 0.05
    raw_log = alert.get("raw_log", "").lower()

    if any(kw in raw_log for kw in ["false positive", "test", "scan"]):
        fp_probability = min(fp_probability + 0.7, 0.95)

    mitre_techniques = []
    if "lateral movement" in raw_log:
        mitre_techniques.append("TA0008")
    if "credential" in raw_log:
        mitre_techniques.append("TA0006")
    if "exfiltration" in raw_log:
        mitre_techniques.append("TA0010")

    return {
        "severity": severity,
        "false_positive_probability": fp_probability,
        "mitre_techniques": mitre_techniques,
        "messages": [f"Triage complete: severity={severity}, fp_prob={fp_probability}"],
    }


async def analysis_agent(state: SOCAgentState) -> dict:
    alert = state.get("alert", {})
    source_ip = alert.get("source_ip", "unknown")
    dest_ip = alert.get("dest_ip", "unknown")

    attack_narrative = (
        f"Alert {alert.get('alert_id', 'N/A')} triggered by rule "
        f"{alert.get('rule_id', 0)}: {alert.get('rule_description', '')}. "
        f"Traffic observed from {source_ip} to {dest_ip}."
    )

    affected_assets = []
    if dest_ip and dest_ip != "unknown":
        affected_assets.append(dest_ip)
    if source_ip and source_ip != "unknown":
        affected_assets.append(source_ip)

    return {
        "attack_narrative": attack_narrative,
        "affected_assets": affected_assets,
        "messages": [f"Analysis complete: {len(affected_assets)} assets affected"],
    }


async def threat_intel_agent(state: SOCAgentState) -> dict:
    from tools import mitre_attack_search, enrich_ioc, opencti_query

    alert = state.get("alert", {})
    mitre_techniques = state.get("mitre_techniques", [])
    source_ip = alert.get("source_ip")

    threat_actor_matches = []
    for technique in mitre_techniques:
        try:
            results = await mitre_attack_search(technique)
            threat_actor_matches.extend(results)
        except Exception:
            pass

    ioc_enrichment = {}
    if source_ip:
        try:
            ioc_enrichment = await enrich_ioc(source_ip)
        except Exception:
            ioc_enrichment = {"status": "enrichment_failed"}

    try:
        opencti_results = await opencti_query(f"[ip-addr:value = '{source_ip}']")
        if opencti_results:
            ioc_enrichment["opencti"] = opencti_results
    except Exception:
        pass

    return {
        "threat_actor_matches": threat_actor_matches,
        "ioc_enrichment": ioc_enrichment,
        "messages": [f"Threat intel: {len(threat_actor_matches)} matches found"],
    }


async def response_agent(state: SOCAgentState) -> dict:
    severity = state.get("severity", "LOW")
    affected_assets = state.get("affected_assets", [])
    ioc_enrichment = state.get("ioc_enrichment", {})

    response_actions = []

    if severity in ("HIGH", "CRITICAL"):
        response_actions.append({
            "action": "isolate_host",
            "target": affected_assets[0] if affected_assets else "unknown",
            "status": "pending",
        })
        response_actions.append({
            "action": "block_ip",
            "target": state.get("alert", {}).get("source_ip", ""),
            "status": "pending",
        })

    if ioc_enrichment.get("positives", 0) > 3:
        response_actions.append({
            "action": "quarantine_endpoint",
            "target": affected_assets[0] if affected_assets else "unknown",
            "status": "pending",
        })

    response_actions.append({
        "action": "create_ticket",
        "target": "soc_queue",
        "status": "completed",
    })

    return {
        "response_actions": response_actions,
        "messages": [f"Response: {len(response_actions)} actions queued"],
    }


async def human_approval_node(state: SOCAgentState) -> dict:
    severity = state.get("severity", "LOW")
    response_actions = state.get("response_actions", [])

    has_high_impact = any(
        a.get("action") in ("isolate_host", "quarantine_endpoint")
        for a in response_actions
    )

    if not has_high_impact or severity in ("LOW", "MEDIUM"):
        return {
            "human_approved": True,
            "approval_timeout": False,
            "messages": ["Auto-approved: low-impact actions"],
        }

    return {
        "human_approved": False,
        "approval_timeout": False,
        "messages": ["Awaiting human approval for high-impact actions"],
    }


async def escalate_agent(state: SOCAgentState) -> dict:
    return {
        "incident_id": f"ESC-{uuid.uuid4().hex[:8].upper()}",
        "final_report": (
            f"ESCALATION REQUIRED\n"
            f"Alert: {state.get('alert', {}).get('alert_id', 'N/A')}\n"
            f"Severity: {state.get('severity', 'UNKNOWN')}\n"
            f"Actions pending: {len(state.get('response_actions', []))}\n"
            f"Human approval timed out."
        ),
        "messages": ["Escalated to senior analyst"],
    }


async def documentation_agent(state: SOCAgentState) -> dict:
    incident_id = state.get("incident_id") or f"INC-{uuid.uuid4().hex[:8].upper()}"

    report_lines = [
        f"INCIDENT REPORT: {incident_id}",
        f"{'=' * 50}",
        f"Alert ID: {state.get('alert', {}).get('alert_id', 'N/A')}",
        f"Rule: {state.get('alert', {}).get('rule_description', 'N/A')}",
        f"Severity: {state.get('severity', 'N/A')}",
        f"FP Probability: {state.get('false_positive_probability', 0.0):.2f}",
        f"MITRE Techniques: {', '.join(state.get('mitre_techniques', [])) or 'None'}",
        f"",
        f"ATTACK NARRATIVE:",
        f"{state.get('attack_narrative', 'N/A')}",
        f"",
        f"AFFECTED ASSETS: {', '.join(state.get('affected_assets', [])) or 'None'}",
        f"",
        f"THREAT ACTOR MATCHES: {len(state.get('threat_actor_matches', []))}",
        f"IOC ENRICHMENT: {bool(state.get('ioc_enrichment', {}))}",
        f"",
        f"RESPONSE ACTIONS:",
    ]

    for action in state.get("response_actions", []):
        report_lines.append(
            f"  - {action.get('action', 'N/A')}: {action.get('target', 'N/A')} [{action.get('status', 'N/A')}]"
        )

    report_lines.extend([
        f"",
        f"HUMAN APPROVED: {state.get('human_approved', False)}",
        f"TIMEOUT: {state.get('approval_timeout', False)}",
        f"{'=' * 50}",
    ])

    return {
        "incident_id": incident_id,
        "final_report": "\n".join(report_lines),
        "messages": [f"Documentation complete: {incident_id}"],
    }
