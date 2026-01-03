# Integrated Vulnerability Management & AI Usage Monitoring System

A comprehensive security platform that unifies traditional vulnerability management with AI usage monitoring and Model Context Protocol (MCP) security oversight, built on AWS Bedrock AgentCore.

## 🎯 Overview

This system addresses the growing security challenges of modern organizations by providing:

- **Unified Vulnerability Management**: Traditional infrastructure vulnerabilities alongside AI-related security risks
- **AI Usage Monitoring**: Real-time tracking of ChatGPT, GitHub Copilot, and other AI tools with policy enforcement
- **MCP Protocol Security**: Monitoring and vulnerability detection for Model Context Protocol communications
- **Integrated Risk Prioritization**: Cross-source risk scoring and business impact assessment
- **Enterprise Integration**: Native integration with Sumo Logic, Rapid7, and Jira for seamless workflows

## 🚀 Quick Start (30-Minute POC)

### Prerequisites
- Python 3.8+
- Terminal/command line access
- Web browser

### Installation & Demo
```bash
# Clone or download the repository
# Navigate to the project directory

# Run the automated setup
chmod +x poc_quick_start.sh
./poc_quick_start.sh

# Start the POC system
./start_poc.sh

# Open your browser to: http://localhost:5000
```

### Demo Scenarios
1. **Unified Dashboard**: View vulnerabilities across all sources
2. **AI Usage Monitoring**: Track policy violations and sensitive data exposure
3. **MCP Security**: Monitor protocol-level vulnerabilities
4. **Real-Time Processing**: Simulate events and see immediate detection
5. **Executive Insights**: Strategic security metrics and compliance reporting

## 📋 System Architecture

### Core Components

#### 1. Vulnerability Management System (`vulnerability_management_system.py`)
- **Asset Discovery Agent**: Eliminates blind spots in asset visibility
- **Risk Prioritization Agent**: Reduces overwhelming vulnerability volume
- **Security Monitoring Agent**: Real-time threat detection and response
- **Compliance Monitoring Agent**: Regulatory compliance tracking
- **Patch Management Agent**: Automated remediation workflows

#### 2. AI Usage Monitoring (`ai_usage_monitoring_system.py`)
- **Developer Monitoring**: GitHub Copilot, CodeWhisperer, IDE extensions
- **Business User Monitoring**: ChatGPT, Claude, Microsoft 365 Copilot
- **Security Analysis**: Sensitive data detection and policy enforcement
- **Productivity Analytics**: ROI measurement and optimization

#### 3. MCP Protocol Monitoring (`mcp_usage_monitoring_system.py`)
- **Protocol Analysis**: JSON-RPC message interception and analysis
- **Vulnerability Detection**: Command injection, credential exposure patterns
- **Server Monitoring**: Health, performance, and security assessment
- **Compliance Management**: Policy enforcement and audit trails

#### 4. Integration Layer (`sumo_rapid7_jira_integrations.py`)
- **Sumo Logic**: Centralized logging and real-time analytics
- **Rapid7 InsightIDR**: Security investigations and threat correlation
- **Jira**: Incident management and remediation workflows

### Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP MONITORING LAYER                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Protocol    │  │ Server      │  │ Client      │        │
│  │ Monitor     │  │ Monitor     │  │ Monitor     │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────┼─────────────────────┼─────────────────┘
                      │                     │
                      ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│                 INTEGRATION BRIDGE                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Vulnerability│  │ Data Format │  │ Workflow    │        │
│  │ Analyzer    │  │ Converter   │  │ Orchestrator│        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────┼─────────────────────┼─────────────────┘
                      │                     │
                      ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│            VULNERABILITY MANAGEMENT SYSTEM                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Asset       │  │ Risk        │  │ Security    │        │
│  │ Discovery   │  │ Prioritization│  │ Monitoring  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────┼─────────────────────┼─────────────────┘
                      │                     │
                      ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│              EXTERNAL INTEGRATIONS                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ Sumo Logic  │  │ Rapid7      │  │ Jira        │        │
│  │ Analytics   │  │ InsightIDR  │  │ Workflows   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Production Deployment

### AWS Bedrock AgentCore Setup

#### Prerequisites
- AWS account with Bedrock AgentCore access
- AWS CLI configured with appropriate permissions
- Python 3.10+ and pip

#### Quick Deployment
```bash
# Install AgentCore toolkit
pip install "bedrock-agentcore-starter-toolkit>=0.1.21" strands-agents boto3

# Configure the system
agentcore configure -e vulnerability_management_system.py

# Deploy to AgentCore
agentcore deploy
```

#### Configuration Options
- **Memory**: Enable long-term memory for persistent vulnerability knowledge
- **Code Interpreter**: Secure Python execution for data analysis
- **Observability**: X-Ray tracing and CloudWatch integration
- **Scaling**: Auto-scaling based on vulnerability volume

### Enterprise Integration

#### Sumo Logic Configuration
```bash
# Create log sources for AI usage monitoring
curl -X POST "https://api.sumologic.com/api/v1/collectors/sources" \
  -H "Authorization: Basic $(echo -n 'accessId:accessKey' | base64)" \
  -d '{"source": {"name": "AI Usage Monitoring", "category": "ai_usage_monitoring"}}'
```

#### Rapid7 Integration
```python
# Configure custom log source for AI security events
rapid7 = Rapid7AISecurityIntegration('your-api-key', 'us')
log_source = rapid7.create_ai_usage_log_source()
```

#### Jira Project Setup
```bash
# Create dedicated project for AI security incidents
curl -X POST "https://company.atlassian.net/rest/api/3/project" \
  -H "Authorization: Basic $(echo -n 'email:token' | base64)" \
  -d '{"key": "AISEC", "name": "AI Security and Compliance"}'
```

## 📊 Key Features

### Vulnerability Management
- **Multi-Source Integration**: Traditional scanners + AI usage + MCP protocol
- **Unified Risk Scoring**: CVSS + business context + AI-specific factors
- **Automated Prioritization**: ML-driven risk assessment and business impact
- **Remediation Workflows**: Automated patch management and containment

### AI Usage Monitoring
- **Comprehensive Coverage**: 
  - Developer tools (GitHub Copilot, CodeWhisperer, Cursor)
  - Business applications (ChatGPT, Claude, Microsoft 365 Copilot)
  - Browser-based AI tools and extensions
- **Security Controls**:
  - Real-time sensitive data detection
  - Policy violation monitoring
  - Shadow AI discovery
  - Compliance framework mapping (GDPR, SOX, HIPAA)

### MCP Protocol Security
- **Protocol Monitoring**: JSON-RPC message interception and analysis
- **Vulnerability Detection**: Command injection, path traversal, credential exposure
- **Server Management**: Health monitoring, configuration analysis, approval workflows
- **Tool Risk Assessment**: Risk scoring based on tool capabilities and usage patterns

### Enterprise Integration
- **Sumo Logic**: Real-time analytics, compliance dashboards, executive reporting
- **Rapid7 InsightIDR**: Security investigations, threat intelligence correlation
- **Jira**: Incident management, compliance workflows, remediation tracking

## 📈 Use Cases

### Organizational Roadblock Solutions

#### 1. Incomplete Asset Visibility → Asset Discovery Agent
- Automated discovery across networks, cloud, and AI infrastructure
- Shadow IT detection including unauthorized AI tools
- Real-time inventory maintenance with dependency mapping

#### 2. Overwhelming Volume → Risk Prioritization Agent
- Business context scoring beyond traditional CVSS
- AI usage risk factors and policy violation weighting
- Dynamic prioritization based on threat landscape

#### 3. Resource Constraints → Cost Optimization Agent
- ROI calculations for security investments
- Automation opportunity identification
- Resource allocation optimization across traditional and AI security

#### 4. Siloed Teams → Collaboration Agent
- Cross-team workflows spanning traditional and AI security
- Stakeholder-specific dashboards and reporting
- Unified incident response procedures

#### 5. Reactive Mindset → Strategic Planning Agent
- Maturity assessment including AI security posture
- Long-term strategy incorporating AI governance
- Proactive risk management across all attack surfaces

#### 6. Legacy Systems → Legacy Systems Agent + MCP Integration
- Traditional system risk management
- Modern AI protocol security (MCP)
- Bridging legacy infrastructure with AI capabilities

#### 7. Patch Delays → Patch Management Agent
- Automated testing for traditional and AI system updates
- MCP server patch management and validation
- Complex environment orchestration

## 🔍 Monitoring & Analytics

### Real-Time Dashboards
- **Executive Overview**: Strategic metrics across all security domains
- **Operational Dashboard**: Active incidents, alerts, and remediation status
- **Compliance View**: Regulatory compliance status and audit trails
- **AI Usage Analytics**: Adoption trends, risk patterns, policy effectiveness

### Key Metrics
- **Vulnerability Metrics**: MTTR, backlog reduction, risk exposure
- **AI Usage Metrics**: Adoption rates, policy compliance, productivity impact
- **MCP Security Metrics**: Protocol usage, server health, vulnerability trends
- **Integration Metrics**: Alert response times, workflow efficiency, cost optimization

### Alerting & Notifications
- **Critical Vulnerabilities**: Immediate escalation for high-risk issues
- **Policy Violations**: Real-time alerts for AI usage policy breaches
- **MCP Security Events**: Protocol-level security incident notifications
- **Compliance Issues**: Regulatory compliance violation alerts

## 🛡️ Security & Compliance

### Security Features
- **Zero Trust Architecture**: Assume breach mentality across all monitoring
- **Encryption**: End-to-end encryption for all monitoring data
- **Access Controls**: Role-based access with audit logging
- **Data Minimization**: Hash-based content analysis to protect privacy

### Compliance Frameworks
- **GDPR**: AI usage monitoring with privacy protection
- **SOX**: Financial system AI usage oversight
- **HIPAA**: Healthcare AI tool compliance monitoring
- **PCI-DSS**: Payment system AI security controls
- **NIST**: Comprehensive cybersecurity framework alignment

### Audit & Reporting
- **Comprehensive Audit Trails**: All events logged with full context
- **Regulatory Reporting**: Automated compliance report generation
- **Executive Reporting**: Strategic security posture and ROI metrics
- **Incident Documentation**: Complete forensic trails for security events

## 📚 Documentation

### Quick References
- **[POC Demo Guide](poc_demo_guide.md)**: 30-minute demonstration walkthrough
- **[Quick Start Guide](quick_start_guide.md)**: Rapid deployment instructions
- **[Deployment Guide](deployment_guide.md)**: Production deployment procedures
- **[Integration Examples](integration_examples.py)**: Real-world integration patterns

### Detailed Documentation
- **[Implementation Roadmap](implementation_roadmap.md)**: Phased deployment strategy
- **[System Architecture](system_architecture.py)**: Technical architecture details
- **[MCP Integration](mcp_vm_integration_architecture.py)**: MCP-specific integration patterns
- **[Usage Examples](usage_examples.py)**: Comprehensive usage scenarios

### Integration Guides
- **[Sumo Logic Integration](sumo_rapid7_jira_integrations.py)**: Analytics and logging setup
- **[Rapid7 Integration](sumo_rapid7_jira_integrations.py)**: Security investigation workflows
- **[Jira Integration](sumo_rapid7_jira_integrations.py)**: Incident management setup

## 🤝 Contributing

### Development Setup
```bash
# Clone repository
git clone <repository-url>
cd integrated-vm-ai-monitoring

# Create development environment
python -m venv dev_env
source dev_env/bin/activate  # Windows: dev_env\Scripts\activate

# Install development dependencies
pip install -r requirements.txt
pip install -r dev-requirements.txt

# Run tests
python -m pytest tests/

# Start development server
python poc_integrated_system.py
```

### Code Structure
```
├── vulnerability_management_system.py    # Core VM system
├── ai_usage_monitoring_system.py        # AI monitoring agents
├── mcp_usage_monitoring_system.py       # MCP protocol monitoring
├── mcp_vulnerability_bridge.py          # MCP-VM integration
├── sumo_rapid7_jira_integrations.py     # Enterprise integrations
├── poc_integrated_system.py             # 30-minute POC
├── monitoring_components.py             # Monitoring infrastructure
├── integration_examples.py              # Usage examples
└── docs/                                # Documentation
```

### Testing
- **Unit Tests**: Component-level testing for all agents
- **Integration Tests**: End-to-end workflow validation
- **Performance Tests**: Scalability and load testing
- **Security Tests**: Vulnerability scanning and penetration testing

## 📞 Support

### Community Support
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community Q&A and best practices
- **Documentation**: Comprehensive guides and examples

### Enterprise Support
- **Professional Services**: Implementation and customization
- **Training**: Team training and certification programs
- **24/7 Support**: Production support and incident response

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **AWS Bedrock AgentCore Team**: Platform and infrastructure support
- **Security Community**: Vulnerability research and best practices
- **AI Safety Researchers**: AI usage monitoring methodologies
- **MCP Protocol Contributors**: Protocol specification and security guidance

---

## 🎯 Getting Started Checklist

- [ ] **Run POC**: Execute `./poc_quick_start.sh` for 30-minute demo
- [ ] **Explore Dashboard**: Navigate to http://localhost:5000
- [ ] **Review Architecture**: Read system architecture documentation
- [ ] **Plan Deployment**: Review implementation roadmap
- [ ] **Configure Integrations**: Set up Sumo Logic, Rapid7, Jira connections
- [ ] **Deploy Production**: Follow deployment guide for AWS setup
- [ ] **Monitor & Optimize**: Use dashboards for ongoing management

**Ready to transform your security posture with integrated vulnerability management and AI usage monitoring!** 🚀