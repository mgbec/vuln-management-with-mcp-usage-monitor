# 30-Minute POC Demo Guide
## Integrated Vulnerability Management & AI Usage Monitoring System

### Overview
This proof of concept demonstrates a unified system that monitors and manages vulnerabilities across:
- **Traditional Infrastructure** (web servers, databases, applications)
- **AI Tool Usage** (ChatGPT, GitHub Copilot, etc.)
- **MCP Protocol** (Model Context Protocol servers and tools)

### Quick Start (5 minutes)

#### Prerequisites
- Python 3.8+ installed
- Terminal/command line access
- Web browser

#### Setup Commands
```bash
# Make setup script executable and run
chmod +x poc_quick_start.sh
./poc_quick_start.sh

# Start the POC system
./start_poc.sh
```

#### Access the System
Open your browser to: **http://localhost:5000**

### Demo Scenarios (25 minutes)

#### Scenario 1: Unified Vulnerability Dashboard (5 minutes)
**Objective**: Show integrated vulnerability management across all sources

1. **Navigate to Vulnerabilities**: http://localhost:5000/vulnerabilities
2. **Observe**: Mixed vulnerability sources (traditional, AI usage, MCP)
3. **Key Points**:
   - Unified risk scoring across all vulnerability types
   - Priority ranking considers source context
   - Traditional SQL injection ranked alongside AI policy violations
   - MCP command injection vulnerabilities elevated in priority

**Expected Results**:
```json
{
  "total_vulnerabilities": 8,
  "vulnerabilities": [
    {
      "event_id": "VULN-001",
      "vulnerability_type": "SQL Injection", 
      "severity": "critical",
      "source": "traditional",
      "priority_rank": 1,
      "risk_score": 9.2
    },
    {
      "event_id": "MCP-a1b2c3d4",
      "vulnerability_type": "command_injection",
      "severity": "critical", 
      "source": "mcp",
      "priority_rank": 1,
      "risk_score": 10.0
    }
  ]
}
```

#### Scenario 2: AI Usage Monitoring (5 minutes)
**Objective**: Demonstrate AI tool usage tracking and policy violation detection

1. **Navigate to AI Usage**: http://localhost:5000/ai-usage
2. **Observe**: AI tool usage events with risk assessment
3. **Key Points**:
   - Real-time monitoring of ChatGPT, GitHub Copilot usage
   - Sensitive data detection in AI interactions
   - Policy violation tracking (external AI usage)
   - User behavior analysis across departments

**Expected Results**:
```json
{
  "total_events": 22,
  "events": [
    {
      "user_id": "john.doe@company.com",
      "ai_tool": "ChatGPT",
      "risk_level": "medium",
      "sensitive_data_detected": true,
      "policy_violations": ["external_ai_usage"]
    }
  ]
}
```

#### Scenario 3: MCP Protocol Security (5 minutes)
**Objective**: Show MCP-specific vulnerability detection and monitoring

1. **Navigate to MCP Events**: http://localhost:5000/mcp-events
2. **Observe**: MCP server interactions and security analysis
3. **Key Points**:
   - Protocol-level monitoring of MCP communications
   - Tool-specific risk assessment (execute_command vs read_file)
   - Vulnerability pattern detection (command injection, path traversal)
   - Server-based risk categorization

**Expected Results**:
```json
{
  "total_events": 17,
  "events": [
    {
      "user_id": "developer@company.com",
      "server_name": "filesystem-server",
      "tool_name": "execute_command",
      "risk_level": "high",
      "vulnerability_patterns": ["command_injection"]
    }
  ]
}
```

#### Scenario 4: Real-Time Event Processing (5 minutes)
**Objective**: Demonstrate real-time vulnerability detection and alerting

1. **Navigate to Event Simulator**: http://localhost:5000/simulate-event
2. **Simulate High-Risk AI Event**:
   - Event Type: AI Usage Event
   - Risk Level: High
   - Include Vulnerability Pattern: ✓ Yes
3. **Submit and observe**:
   - Check Alerts: http://localhost:5000/alerts
   - Refresh Vulnerabilities: http://localhost:5000/vulnerabilities
4. **Simulate MCP Command Injection**:
   - Event Type: MCP Event
   - Risk Level: High
   - Include Vulnerability Pattern: ✓ Yes

**Expected Workflow**:
1. Event simulated → Stored in database
2. Monitoring loop detects new event (30-second cycle)
3. Vulnerability analyzer processes event
4. New vulnerability created if patterns match
5. Alert generated for high-severity issues
6. Updated data visible in web interface

#### Scenario 5: Executive Dashboard (5 minutes)
**Objective**: Show integrated metrics and strategic insights

1. **Navigate to Dashboard**: http://localhost:5000/dashboard
2. **Observe**: Cross-system metrics and trends
3. **Key Points**:
   - Vulnerability breakdown by source and severity
   - AI usage risk distribution
   - MCP security event trends
   - Integrated compliance and risk metrics

**Expected Results**:
```json
{
  "vulnerability_summary": [
    {"source": "traditional", "severity": "critical", "count": 1},
    {"source": "ai_usage", "severity": "high", "count": 2},
    {"source": "mcp", "severity": "critical", "count": 1}
  ],
  "ai_usage_summary": [
    {"risk_level": "high", "count": 5},
    {"risk_level": "medium", "count": 12},
    {"risk_level": "low", "count": 8}
  ]
}
```

### Key Integration Points Demonstrated

#### 1. Unified Risk Scoring
- **Traditional vulnerabilities**: CVSS-based scoring
- **AI usage risks**: Policy violation + sensitive data factors
- **MCP vulnerabilities**: Protocol-specific risk assessment
- **Result**: Comparable risk scores across all sources

#### 2. Cross-Source Correlation
- **User Context**: Same user across AI tools and MCP servers
- **Asset Relationships**: MCP servers as infrastructure assets
- **Timeline Correlation**: Events processed in chronological order
- **Impact Assessment**: Business impact considers all vulnerability sources

#### 3. Integrated Alerting
- **Single Alert Stream**: All high-priority issues in one queue
- **Context Preservation**: Alerts maintain source-specific details
- **Escalation Logic**: Consistent severity-based escalation
- **Assignment Rules**: Route to appropriate teams based on source

#### 4. Compliance Integration
- **Framework Mapping**: GDPR, SOX, HIPAA across all sources
- **Audit Trails**: Complete event history for compliance
- **Policy Enforcement**: Consistent policy application
- **Reporting**: Unified compliance dashboards

### Technical Architecture Highlights

#### Database Integration
```sql
-- Unified vulnerabilities table
CREATE TABLE vulnerabilities (
    event_id TEXT UNIQUE,
    source TEXT,  -- 'traditional', 'ai_usage', 'mcp'
    severity TEXT,
    risk_score REAL,
    compliance_impact TEXT
);
```

#### Risk Calculation
```python
def _calculate_ai_risk_score(self, ai_event):
    base_score = 5.0
    if ai_event.sensitive_data_detected:
        base_score += 3.0  # Sensitive data penalty
    if ai_event.policy_violations:
        base_score += len(ai_event.policy_violations) * 1.0
    return min(base_score, 10.0)
```

#### Real-Time Processing
```python
def _monitoring_loop(self):
    while self.monitoring_active:
        self._process_new_ai_events()      # AI usage analysis
        self._process_new_mcp_events()     # MCP vulnerability detection
        self._generate_priority_alerts()   # Cross-source alerting
        time.sleep(30)  # 30-second monitoring cycle
```

### Next Steps for Full Implementation

#### Immediate (Week 1-2)
- Deploy to AWS with Bedrock AgentCore
- Connect to real AI tool APIs (GitHub, Microsoft, etc.)
- Implement actual MCP protocol monitoring
- Add Sumo Logic, Rapid7, Jira integrations

#### Short-term (Month 1-2)
- Scale monitoring infrastructure
- Add machine learning for anomaly detection
- Implement automated remediation workflows
- Develop comprehensive compliance reporting

#### Long-term (Month 3-6)
- Multi-tenant architecture for large organizations
- Advanced threat intelligence integration
- Predictive risk modeling
- Full enterprise governance framework

### Troubleshooting

#### Common Issues
1. **Port 5000 in use**: Change port in `poc_integrated_system.py` line with `app.run(port=5001)`
2. **Database locked**: Stop any running instances and restart
3. **Missing dependencies**: Run `pip install -r poc_requirements.txt`
4. **Permission errors**: Ensure scripts are executable with `chmod +x`

#### Verification Commands
```bash
# Check if system is running
curl http://localhost:5000/dashboard

# View database contents
sqlite3 poc_integrated.db "SELECT COUNT(*) FROM vulnerabilities;"

# Check logs
tail -f nohup.out  # If running in background
```

### Success Metrics

#### POC Objectives Met
- ✅ **Unified Vulnerability Management**: All sources in single interface
- ✅ **Real-Time Processing**: 30-second detection and analysis cycle
- ✅ **Cross-Source Correlation**: User and asset context preserved
- ✅ **Integrated Risk Scoring**: Comparable metrics across sources
- ✅ **Executive Visibility**: Strategic dashboard with actionable insights

#### Demonstrated Value
- **Operational Efficiency**: Single pane of glass for all vulnerabilities
- **Risk Reduction**: Faster detection and prioritization
- **Compliance Assurance**: Comprehensive audit trails and reporting
- **Strategic Planning**: Data-driven security investment decisions

This POC demonstrates the core value proposition of integrated vulnerability management across traditional infrastructure, AI tool usage, and emerging protocols like MCP.