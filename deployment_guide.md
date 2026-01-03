# Vulnerability Management System Deployment Guide

## Overview

This Bedrock AgentCore system addresses the 7 major organizational roadblocks in vulnerability management through specialized AI agents:

1. **Asset Discovery Agent** - Eliminates blind spots in asset visibility
2. **Risk Prioritization Agent** - Reduces overwhelming vulnerability volume  
3. **Resource Optimization Agent** - Maximizes ROI within budget constraints
4. **Collaboration Agent** - Breaks down team silos and improves communication
5. **Strategic Planning Agent** - Shifts from reactive to proactive approaches
6. **Legacy Systems Agent** - Manages technical debt and unpatchable systems
7. **Patch Management Agent** - Accelerates testing and deployment processes

## Prerequisites

- AWS account with Bedrock AgentCore access
- Python 3.10+
- AWS CLI configured
- Bedrock model access enabled

## Quick Deployment

### 1. Install Dependencies

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install packages
pip install "bedrock-agentcore-starter-toolkit>=0.1.21" strands-agents strands-agents-tools boto3 pandas numpy matplotlib seaborn
```

### 2. Configure the System

```bash
agentcore configure -e vulnerability_management_system.py

# When prompted:
# - Execution Role: Press Enter to auto-create
# - ECR Repository: Press Enter to auto-create  
# - Requirements File: Confirm requirements.txt
# - OAuth Configuration: Type 'no'
# - Request Header Allowlist: Type 'no'
# - Memory Configuration: Type 'yes' for long-term memory
```

### 3. Deploy to AgentCore

```bash
agentcore deploy

# This creates:
# - Memory resources for persistent vulnerability knowledge
# - Container deployment with all dependencies
# - Runtime endpoint with observability enabled
```

## Usage Patterns

### Asset Discovery
```bash
agentcore invoke '{
  "request_type": "asset_discovery",
  "query": "Identify all unmanaged cloud resources",
  "data": {"aws_accounts": ["123456789"]},
  "actor_id": "security-team"
}'
```

### Risk Prioritization
```bash
agentcore invoke '{
  "request_type": "risk_prioritization", 
  "query": "Prioritize 2000 vulnerabilities for patching",
  "data": {"scan_results": "vulnerability_data.json"},
  "actor_id": "security-team"
}'
```

### Resource Optimization
```bash
agentcore invoke '{
  "request_type": "resource_optimization",
  "query": "Optimize team allocation and tool spending",
  "data": {"budget": 500000, "team_size": 8},
  "actor_id": "security-manager"
}'
```

## Key Features

### Persistent Memory
- **Asset Knowledge**: Maintains comprehensive asset inventory across sessions
- **Vulnerability History**: Tracks vulnerability trends and remediation patterns
- **Process Learning**: Remembers successful workflows and optimizations
- **Metrics Storage**: Preserves KPIs and performance data

### Code Execution Capabilities
- **Data Analysis**: Process vulnerability scans, asset inventories, and metrics
- **Visualization**: Create charts, graphs, and dashboards
- **Modeling**: Build risk models and ROI calculations
- **Automation**: Generate scripts and configuration files

### Cross-Agent Coordination
- **Intelligent Routing**: Automatically routes queries to appropriate specialists
- **Context Sharing**: Agents share relevant information through memory
- **Workflow Integration**: Coordinates multi-step processes across agents

## Monitoring and Observability

### View System Status
```bash
agentcore status
# Shows memory resources, deployment status, and observability links
```

### Access Logs and Traces
```bash
# View detailed execution logs
aws logs tail /aws/bedrock-agentcore/runtimes/AGENT_ID-DEFAULT --follow

# Access CloudWatch dashboard for traces and metrics
# URL provided in agentcore status output
```

## Integration Examples

### SIEM Integration
```python
# Send prioritized vulnerabilities to SIEM
siem_payload = {
    "request_type": "risk_prioritization",
    "query": "Generate SIEM alerts for critical vulnerabilities",
    "data": {"siem_format": "splunk", "alert_threshold": "critical"}
}
```

### Ticketing System Integration  
```python
# Create prioritized remediation tickets
ticket_payload = {
    "request_type": "collaboration",
    "query": "Generate ServiceNow tickets for top 20 vulnerabilities",
    "data": {"ticket_system": "servicenow", "assignment_rules": "auto"}
}
```

### Dashboard Integration
```python
# Generate executive dashboard data
dashboard_payload = {
    "request_type": "strategic_planning", 
    "query": "Create executive vulnerability metrics dashboard",
    "data": {"dashboard_type": "executive", "time_period": "quarterly"}
}
```

## Cleanup

```bash
agentcore destroy
# Removes all resources: runtime, memory, ECR repository, IAM roles
```

## Troubleshooting

### Memory Issues
- Ensure memory is ACTIVE before testing cross-session features
- Wait 15-30 seconds after storing data for extraction to complete

### Performance Optimization
- Use specific request_types for faster routing
- Include relevant data in payload to reduce API calls
- Monitor CloudWatch metrics for optimization opportunities

### Integration Issues
- Verify IAM permissions for external system access
- Check network connectivity for on-premises integrations
- Review logs for API authentication errors