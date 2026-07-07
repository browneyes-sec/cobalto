# Evidence Artifact Schema

All certification evidence artifacts must conform to this JSON schema for machine-verifiability and chain-of-custody tracking.

## Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": [
    "artifact_id", "control_id", "domain", "procedure",
    "timestamp", "status", "result", "chain_of_custody"
  ],
  "properties": {
    "artifact_id": {
      "type": "string",
      "description": "Unique identifier for this artifact (UUID v4)"
    },
    "control_id": {
      "type": "string",
      "pattern": "^(PE|PI|SC|RS|CM|OB)-\\d{2}$",
      "description": "The control being validated"
    },
    "domain": {
      "type": "string",
      "enum": ["performance", "pipeline-integrity", "security", "resilience", "compliance", "observability"]
    },
    "procedure": {
      "type": "string",
      "description": "Procedure script that generated this evidence"
    },
    "timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp of evidence collection"
    },
    "status": {
      "type": "string",
      "enum": ["pass", "fail", "error", "skipped"],
      "description": "Overall control status"
    },
    "result": {
      "type": "object",
      "properties": {
        "metric_name": {"type": "string"},
        "observed_value": {"type": ["number", "string", "boolean"]},
        "threshold": {"type": ["number", "string"], "description": "Expected pass/fail threshold"},
        "passed": {"type": "boolean"},
        "details": {"type": "string", "description": "Human-readable explanation"}
      },
      "required": ["passed", "details"]
    },
    "chain_of_custody": {
      "type": "object",
      "required": ["runner", "hostname", "environment", "collection_method"],
      "properties": {
        "runner": {"type": "string", "description": "User or service that ran the procedure"},
        "hostname": {"type": "string"},
        "environment": {"type": "string", "enum": ["dev", "staging", "production"]},
        "collection_method": {"type": "string", "description": "How evidence was gathered (e.g., API call, log parse, script output)"},
        "signature": {"type": "string", "description": "HMAC-SHA256 of the artifact body for tamper evidence"}
      }
    }
  }
}
```

## File Naming Convention

```
certification/evidence/{domain}/{control-id}_{timestamp}.json
```

Example: `certification/evidence/pipeline/PI-01_2026-07-07T14-00-00Z.json`

## Chain of Custody

Each artifact must include a `chain_of_custody.signature` field containing an HMAC-SHA256 hash of the artifact body (all fields except the signature itself). This ensures:

1. **Non-repudiation**: The runner cannot deny generating the artifact
2. **Integrity**: The artifact has not been modified after generation
3. **Auditability**: Full provenance chain for compliance auditors
