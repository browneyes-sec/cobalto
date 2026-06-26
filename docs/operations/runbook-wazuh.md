# Operations Runbook: Wazuh Manager

## Wazuh Manager Troubleshooting

### Service Status

```bash
# Check Wazuh manager status
systemctl status wazuh-manager

# View recent logs
journalctl -u wazuh-manager --since "1 hour ago" --no-pager

# Check if API is responding
curl -k -s https://localhost:55000/security/user/authenticate -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" | jq .
```

### Common Issues

#### Manager won't start

1. Check disk space: `df -h`
2. Check ElasticSearch connectivity: `curl -s http://localhost:9200/_cluster/health`
3. Verify config: `/var/ossec/etc/ossec.conf`
4. Check for port conflicts: `ss -tlnp | grep 1514`

#### High memory usage

1. Check active agent count: `curl -s https://localhost:55000/agents -H "Authorization: Bearer $TOKEN" | jq .total_affected_items`
2. Reduce `analysisd.queue_size` in `ossec.conf` if queue is full
3. Restart manager after config changes

#### Alert storm / log flooding

1. Check which rules are generating most alerts: `tail -f /var/ossec/logs/alerts/alerts.log | grep "Rule:" | sort | uniq -c | sort -rn`
2. Temporarily disable noisy rules: edit `/var/ossec/etc/rules/local_rules.xml`
3. Add threshold-based rules to suppress duplicates

## Agent Enrollment

### Manual enrollment

```bash
# On the manager, add the agent
/var/ossec/bin/manage_agents -a <agent_name> <agent_ip> any

# On the endpoint, install and configure
wget https://packages.wazuh.com/4.x/wazuh-agent/install.sh
WAZUH_MANAGER=<manager_ip> bash install.sh

# Start agent
systemctl start wazuh-agent
```

### Verify enrollment

```bash
# On manager
curl -s https://localhost:55000/agents -H "Authorization: Bearer $TOKEN" | jq '.data[] | select(.name=="<agent_name>")'
```

### Agent not connecting

1. Check agent status: `systemctl status wazuh-agent`
2. Verify manager IP in agent config: `/var/ossec/etc/ossec.conf`
3. Check firewall rules (port 1514/TCP, 1515/TCP for enrollment)
4. Check agent key validity: `/var/ossec/bin/manage_agents -l`

## Log Investigation

### Viewing alerts

```bash
# Real-time alert stream
tail -f /var/ossec/logs/alerts/alerts.log

# Search for specific agent
grep "agent_name:'web-server-01'" /var/ossec/logs/alerts/alerts.log

# Search by rule ID
grep "id:'800100'" /var/ossec/logs/alerts/alerts.log

# JSON format
tail -f /var/ossec/logs/alerts/alerts.json | jq .
```

### Investigating a specific alert

```bash
# Find alert by ID
grep "alert_id:'WAZUH-XXXX'" /var/ossec/logs/alerts/alerts.log

# Get full context (surrounding 20 lines)
grep -n -B5 -A20 "alert_id:'WAZUH-XXXX'" /var/ossec/logs/alerts/alerts.log

# Cross-reference with archive logs
grep "srcip:'10.0.0.50'" /var/ossec/logs/archives/archives.log | tail -50
```

### Performance metrics

```bash
# Check analysis daemon stats
/var/ossec/bin/analysisd -s

# Check remoted stats (agent connections)
cat /var/ossec/logs/remoted.log | tail -20

# Disk usage for alert storage
du -sh /var/ossec/logs/alerts/
```

## Escalation

- If manager crashes repeatedly: collect `/var/ossec/logs/` and `/var/ossec/var/db/` for analysis
- If agent enrollment fails across fleet: check network policy, DNS resolution, and manager certificate
- For data loss concerns: verify ElasticSearch snapshots and Wazuh backup configuration
