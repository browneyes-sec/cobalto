# Playbook Engine

## Overview

The Playbook Engine provides YAML-based automation for security response workflows. Features version management, template variables, and conditional execution.

```
+----------------------------------------------------+
|                 PLAYBOOK ENGINE                     |
|                                                    |
|  +----------------------------------------------+  |
|  | YAML Parser                                  |  |
|  | - Load .yaml files                           |  |
|  | - Validate schema                            |  |
|  | - Serialize back to YAML                     |  |
|  +----------------------------------------------+  |
|  | Template Engine                              |  |
|  | - {{variable}} substitution                  |  |
|  | - Nested object support                      |  |
|  | - List rendering                             |  |
|  +----------------------------------------------+  |
|  | Version Manager                              |  |
|  | - Track version history                      |  |
|  | - Compare versions                           |  |
|  | - Revert to previous                         |  |
|  +----------------------------------------------+  |
|  | Execution Engine                             |  |
|  | - Sequential actions                         |  |
|  | - Parallel actions                           |  |
|  | - Conditional execution                      |  |
|  | - Approval gates                             |  |
|  +----------------------------------------------+  |
+----------------------------------------------------+
```

## YAML DSL

### Basic Structure

```yaml
metadata:
  id: "brute-force-response"
  name: Brute Force Attack Response
  version: "1.0.0"
  author: SOC Team
  status: active
  tags:
    - brute-force
    - authentication
  triggers:
    - "rule_id == 5712"
    - "rule_level >= 8"

steps:
  - name: Triage
    description: Initial alert triage
    actions:
      - name: Parse Alert
        action_type: enrich
        parameters:
          type: parse_alert
          alert_id: "{{alert_id}}"

  - name: Response
    condition: "severity >= 7"
    actions:
      - name: Block IP
        action_type: block_ip
        parameters:
          ip: "{{source_ip}}"
        requires_approval: true
```

### Metadata Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | str | Yes | Unique identifier |
| `name` | str | Yes | Human-readable name |
| `version` | str | Yes | Semver version |
| `author` | str | No | Author name |
| `status` | str | No | draft/active/paused/deprecated |
| `tags` | list | No | Classification tags |
| `triggers` | list | No | Alert matching rules |
| `min_cobalto_version` | str | No | Minimum platform version |

### Action Types

| Type | Description | Example Parameters |
|------|-------------|-------------------|
| `block_ip` | Block IP address | `ip`, `duration`, `reason` |
| `isolate_host` | Isolate host | `host`, `duration`, `reason` |
| `disable_user` | Disable user account | `username`, `reason` |
| `quarantine_file` | Quarantine file | `file_path`, `file_hash` |
| `collect_evidence` | Collect forensics | `type`, `host`, `time_range` |
| `notify` | Send notification | `channel`, `message`, `priority` |
| `escalate` | Escalate to human | `reason`, `assignee` |
| `enrich` | Enrich with data | `type`, `parameters` |
| `query` | Query data source | `type`, `parameters` |
| `webhook` | Call webhook | `url`, `method`, `body` |
| `custom` | Custom action | `type`, `parameters` |

### Template Variables

```yaml
# Simple variable
parameters:
  ip: "{{source_ip}}"

# Nested variable
parameters:
  ip: "{{network.src_ip}}"

# List with variables
parameters:
  recipients:
    - "{{escalation_email}}"
    - "#soc-alerts"
```

### Conditional Execution

```yaml
# Step condition
- name: High Severity Response
  condition: "severity >= 7"
  actions:
    - name: Block IP
      action_type: block_ip

# Action condition
- name: Conditional Notify
  action_type: notify
  condition: "alert_type == 'malware'"
  parameters:
    channel: "#malware-alerts"
```

### Parallel Actions

```yaml
- name: Investigation
  parallel: true
  actions:
    - name: Query Threat Intel
      action_type: query
      parameters:
        type: threat_intel
    - name: Check Reputation
      action_type: query
      parameters:
        type: reputation
```

## Version Manager

### Track Versions

```python
from cobalto.soar.playbook import PlaybookEngine

engine = PlaybookEngine()

# Load playbook
playbook = engine.load_playbook_from_yaml("playbooks/brute-force.yaml")

# Save version
version_manager = engine.get_version_manager()
version = version_manager.save_version(
    playbook,
    created_by="admin",
    changes="Added new IOC check",
)
```

### Compare Versions

```python
# Compare two versions
comparison = version_manager.compare_versions(
    "brute-force-response",
    "1.0.0",
    "1.1.0",
)

print(comparison)
# {
#   "version1": "1.0.0",
#   "version2": "1.1.0",
#   "checksum_match": false,
#   "v1_changes": "Initial version",
#   "v2_changes": "Added new IOC check",
# }
```

### Revert Version

```python
# Revert to previous version
reverted = version_manager.revert_to_version(
    "brute-force-response",
    "1.0.0",
)

# reverted is a Playbook object with v1.0.0 content
```

## Execution

### Run Playbook

```python
# Register action handlers
async def block_ip_handler(params, context):
    ip = params["ip"]
    duration = params.get("duration", "24h")
    # Execute blocking
    return {"blocked": True, "ip": ip}

engine.register_action_handler(ActionType.BLOCK_IP, block_ip_handler)

# Execute playbook
execution = await engine.execute(
    playbook_id="brute-force-response",
    context={
        "alert_id": "alert-123",
        "source_ip": "203.0.113.45",
        "severity": 8,
    },
)

print(execution.status)  # "active"
print(execution.action_results)  # {...}
```

## Sample Playbooks

| Playbook | File | Purpose |
|----------|------|---------|
| Brute Force | `playbooks/brute-force-response.yaml` | Block brute force attacks |
| Malware | `playbooks/malware-detection-response.yaml` | Contain malware |
| Phishing | `playbooks/phishing-response.yaml` | Handle phishing emails |

## Loading Playbooks

```python
# Load single playbook
playbook = engine.load_playbook_from_yaml("playbooks/brute-force.yaml")

# Load all playbooks from directory
playbooks = engine.load_playbooks_from_directory("playbooks/")

# List loaded playbooks
for p in engine.list_playbooks():
    print(f"{p['name']} v{p['version']}")
```

## Configuration

```bash
# Playbook settings
PLAYBOOK_STORAGE_PATH=.playbook_versions
PLAYBOOK_DEFAULT_TIMEOUT=300
```

## Testing

```bash
# Run playbook tests
python -m pytest tests/unit/soar/test_playbook_enhanced.py -v
```
