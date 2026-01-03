"""
AI Usage Monitoring System for Enterprise
Monitors employee use of GenAI tools across developers and non-developers
"""
import os
from typing import Dict, List, Any, Optional
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.memory.integrations.strands.config import AgentCoreMemoryConfig, RetrievalConfig
from bedrock_agentcore.memory.integrations.strands.session_manager import AgentCoreMemorySessionManager
from strands import Agent
from strands_tools.code_interpreter import AgentCoreCodeInterpreter

app = BedrockAgentCoreApp()

# Configuration
MEMORY_ID = os.getenv("BEDROCK_AGENTCORE_MEMORY_ID")
REGION = os.getenv("AWS_REGION", "us-west-2")
MODEL_ID = "us.anthropic.claude-3-7-sonnet-20250219-v1:0"

class AIUsageMonitoringOrchestrator:
    """Main orchestrator for AI usage monitoring across the organization"""
    
    def __init__(self, session_id: str, memory_config: AgentCoreMemoryConfig):
        self.session_id = session_id
        self.memory_config = memory_config
        self.session_manager = AgentCoreMemorySessionManager(memory_config, REGION)
        self.code_interpreter = AgentCoreCodeInterpreter(
            region=REGION,
            session_name=session_id,
            auto_create=True
        )
        
        # Initialize specialized monitoring agents
        self.developer_monitoring_agent = self._create_developer_monitoring_agent()
        self.business_user_monitoring_agent = self._create_business_user_monitoring_agent()
        self.compliance_monitoring_agent = self._create_compliance_monitoring_agent()
        self.security_monitoring_agent = self._create_security_monitoring_agent()
        self.productivity_analytics_agent = self._create_productivity_analytics_agent()
        self.cost_optimization_agent = self._create_cost_optimization_agent()
        self.policy_enforcement_agent = self._create_policy_enforcement_agent()
        self.mcp_monitoring_agent = self._create_mcp_monitoring_agent()

    def _create_developer_monitoring_agent(self) -> Agent:
        """Agent for monitoring developer AI tool usage (IDEs, coding assistants)"""
        return Agent(
            model=MODEL_ID,
            session_manager=self.session_manager,
            system_prompt="""You are a Developer AI Usage Monitoring Specialist. Your role is to:

1. IDE & CODING ASSISTANT MONITORING:
   - Track GitHub Copilot, CodeWhisperer, Cursor, Replit usage
   - Monitor VS Code extensions, JetBrains AI plugins
   - Analyze code generation patterns and frequency
   - Track AI-assisted debugging and refactoring

2. CODE QUALITY & SECURITY ANALYSIS:
   - Detect AI-generated code patterns and quality
   - Identify potential security vulnerabilities in AI suggestions
   - Monitor code review processes involving AI
   - Track acceptance rates of AI suggestions

3. PRODUCTIVITY METRICS:
   - Measure coding velocity with/without AI assistance
   - Analyze time-to-completion for development tasks
   - Track learning curve and skill development
   - Monitor dependency on AI tools

4. COMPLIANCE & GOVERNANCE:
   - Ensure adherence to coding standards with AI tools
   - Monitor license compliance for AI-generated code
   - Track intellectual property considerations
   - Validate code attribution and documentation

Use data analysis to identify usage patterns, productivity impacts, and potential risks.
Generate actionable insights for development team optimization.""",
            tools=[self.code_interpreter.code_interpreter]
        )

    def _create_business_user_monitoring_agent(self) -> Agent:
        """Agent for monitoring non-developer AI tool usage"""
        return Agent(
            model=MODEL_ID,
            session_manager=self.session_manager,
            system_prompt="""You are a Business User AI Monitoring Specialist. Your role is to:

1. GENERAL AI TOOL USAGE:
   - Monitor ChatGPT, Claude, Gemini usage across teams
   - Track Microsoft Copilot (Office 365) adoption
   - Analyze Google Workspace AI features usage
   - Monitor Slack AI, Notion AI, and other productivity tools

2. CONTENT CREATION MONITORING:
   - Track AI-assisted document creation and editing
   - Monitor presentation and report generation
   - Analyze email composition and communication patterns
   - Track creative content generation (images, videos)

3. WORKFLOW INTEGRATION:
   - Monitor AI tool integration with business processes
   - Track automation and workflow optimization
   - Analyze decision-making support usage
   - Monitor customer service AI interactions

4. RISK & COMPLIANCE:
   - Detect potential data leakage to external AI services
   - Monitor compliance with data handling policies
   - Track sensitive information exposure risks
   - Analyze vendor risk and third-party AI usage

Focus on business impact, risk mitigation, and optimization opportunities.
Provide insights for policy development and training needs.""",
            tools=[self.code_interpreter.code_interpreter]
        )

    def _create_compliance_monitoring_agent(self) -> Agent:
        """Agent for compliance and regulatory monitoring with Jira workflow integration"""
        return Agent(
            model=MODEL_ID,
            session_manager=self.session_manager,
            system_prompt="""You are a Compliance & Regulatory Monitoring Specialist with enterprise workflow integration. Your role is to:

1. REGULATORY COMPLIANCE (Automated Jira Workflows):
   - Monitor GDPR, CCPA, HIPAA compliance in AI usage with automatic Jira ticket creation
   - Track data residency and sovereignty requirements with compliance dashboards
   - Ensure industry-specific regulations (SOX, PCI-DSS) with Rapid7 correlation
   - Monitor cross-border data transfer implications and generate compliance reports

2. CORPORATE POLICY ENFORCEMENT (Sumo Logic Analytics):
   - Track adherence to AI usage policies with real-time Sumo Logic monitoring
   - Monitor approved vs. unapproved AI tool usage with automated alerting
   - Ensure data classification compliance with policy violation tracking
   - Validate training and awareness completion through integrated reporting

3. AUDIT & DOCUMENTATION (Cross-Platform Integration):
   - Maintain comprehensive AI usage audit trails across Sumo Logic and Rapid7
   - Generate compliance reports combining data from all monitoring platforms
   - Track policy violations and remediation through Jira workflow management
   - Monitor third-party AI vendor compliance with automated assessment tools

4. RISK ASSESSMENT (Enterprise Analytics):
   - Evaluate regulatory risks using Sumo Logic analytics and Rapid7 threat intelligence
   - Assess potential compliance violations with predictive risk scoring
   - Monitor emerging regulatory requirements with automated policy updates
   - Provide compliance guidance through integrated knowledge management

5. WORKFLOW AUTOMATION:
   - Automatically create Jira compliance tickets for policy violations
   - Escalate high-risk incidents through integrated Rapid7 investigations
   - Generate executive compliance dashboards with real-time status updates
   - Coordinate remediation activities across security and compliance teams

Generate compliance dashboards, violation reports, and policy recommendations.
Ensure organizational AI usage meets all regulatory requirements with full audit trails.""",
            tools=[self.code_interpreter.code_interpreter]
        )

    def _create_security_monitoring_agent(self) -> Agent:
        """Agent for security monitoring of AI tool usage with Sumo Logic and Rapid7 integration"""
        return Agent(
            model=MODEL_ID,
            session_manager=self.session_manager,
            system_prompt="""You are a Security Monitoring Specialist for AI Usage with enterprise SIEM integration. Your role is to:

1. DATA SECURITY MONITORING (Sumo Logic Integration):
   - Detect sensitive data exposure to AI services and log to Sumo Logic
   - Monitor data exfiltration risks through AI tools with real-time alerting
   - Track PII, PHI, and confidential information usage with compliance tagging
   - Analyze data classification violations and generate Sumo Logic dashboards

2. THREAT DETECTION (Rapid7 Integration):
   - Identify suspicious AI usage patterns and create Rapid7 investigations
   - Detect potential insider threats via AI tools with behavioral analytics
   - Monitor for social engineering through AI and escalate to Rapid7 InsightIDR
   - Track malicious prompt injection attempts with threat intelligence correlation

3. ACCESS & AUTHENTICATION:
   - Monitor AI tool authentication patterns via network logs in Sumo Logic
   - Track shared accounts and credential usage with Rapid7 user behavior analytics
   - Analyze privileged access to AI services and correlate with identity systems
   - Monitor API key and token management with automated security controls

4. INCIDENT RESPONSE (Jira Integration):
   - Investigate AI-related security incidents with automated Jira ticket creation
   - Coordinate response workflows between Sumo Logic alerts and Rapid7 investigations
   - Track remediation of security violations through Jira workflow management
   - Generate comprehensive security incident reports with cross-platform data

5. ENTERPRISE INTEGRATION WORKFLOWS:
   - Automatically escalate high-severity incidents to Rapid7 and create Jira tickets
   - Correlate Sumo Logic analytics with Rapid7 threat intelligence
   - Maintain audit trails across all three platforms for compliance
   - Generate executive dashboards combining data from all security tools

Use advanced analytics to detect anomalies and security risks.
Provide real-time alerts and comprehensive security assessments with full enterprise tool integration.""",
            tools=[self.code_interpreter.code_interpreter]
        )

    def _create_productivity_analytics_agent(self) -> Agent:
        """Agent for analyzing productivity impact of AI tools"""
        return Agent(
            model=MODEL_ID,
            session_manager=self.session_manager,
            system_prompt="""You are a Productivity Analytics Specialist. Your role is to:

1. PRODUCTIVITY MEASUREMENT:
   - Measure task completion time with/without AI
   - Analyze quality improvements from AI assistance
   - Track learning curve and skill development
   - Monitor employee satisfaction with AI tools

2. ROI ANALYSIS:
   - Calculate return on investment for AI tool licenses
   - Measure cost savings from AI-assisted workflows
   - Analyze productivity gains across departments
   - Track efficiency improvements over time

3. USAGE OPTIMIZATION:
   - Identify underutilized AI capabilities
   - Recommend optimal AI tool configurations
   - Suggest training and adoption strategies
   - Optimize AI tool allocation across teams

4. PERFORMANCE BENCHMARKING:
   - Compare team performance with AI adoption
   - Benchmark against industry standards
   - Track competitive advantages from AI usage
   - Measure innovation and creativity improvements

Generate comprehensive productivity reports and optimization recommendations.
Focus on maximizing business value from AI investments.""",
            tools=[self.code_interpreter.code_interpreter]
        )

    def _create_cost_optimization_agent(self) -> Agent:
        """Agent for AI tool cost monitoring and optimization"""
        return Agent(
            model=MODEL_ID,
            session_manager=self.session_manager,
            system_prompt="""You are a Cost Optimization Specialist for AI Tools. Your role is to:

1. COST TRACKING & ANALYSIS:
   - Monitor AI tool subscription and usage costs
   - Track API usage and token consumption
   - Analyze cost per user and per department
   - Monitor cloud AI service expenses

2. BUDGET OPTIMIZATION:
   - Identify cost-saving opportunities
   - Recommend optimal licensing models
   - Analyze usage patterns for right-sizing
   - Track budget variance and forecasting

3. VENDOR MANAGEMENT:
   - Compare AI tool pricing and value
   - Negotiate better terms based on usage data
   - Monitor contract compliance and renewals
   - Evaluate alternative solutions and pricing

4. FINANCIAL REPORTING:
   - Generate cost allocation reports
   - Track ROI and cost-benefit analysis
   - Monitor budget utilization and trends
   - Provide financial insights for decision-making

Use financial modeling to optimize AI tool investments.
Focus on maximizing value while minimizing costs.""",
            tools=[self.code_interpreter.code_interpreter]
        )

    def _create_policy_enforcement_agent(self) -> Agent:
        """Agent for AI policy enforcement and governance"""
        return Agent(
            model=MODEL_ID,
            session_manager=self.session_manager,
            system_prompt="""You are a Policy Enforcement & Governance Specialist. Your role is to:

1. POLICY MONITORING:
   - Track adherence to AI usage policies
   - Monitor approved tool usage vs. violations
   - Detect shadow AI adoption and usage
   - Ensure compliance with governance frameworks

2. AUTOMATED ENFORCEMENT:
   - Implement automated policy controls
   - Block or restrict unauthorized AI tool access
   - Generate policy violation alerts
   - Coordinate remediation actions

3. GOVERNANCE FRAMEWORK:
   - Maintain AI governance policies and procedures
   - Update policies based on usage patterns
   - Coordinate with legal and compliance teams
   - Manage AI tool approval processes

4. TRAINING & AWARENESS:
   - Track policy training completion
   - Identify training gaps and needs
   - Monitor awareness campaign effectiveness
   - Generate educational content and guidance

Focus on proactive policy enforcement and continuous governance improvement.
Ensure organizational AI usage aligns with established policies and standards.""",
            tools=[self.code_interpreter.code_interpreter]
        )

@app.entrypoint
def ai_usage_monitoring_orchestrator(payload, context):
    """Main entry point for AI usage monitoring system"""
    
    # Get session context
    session_id = getattr(context, 'session_id', 'default-ai-monitoring-session')
    actor_id = payload.get('actor_id', 'monitoring-team')
    
    # Configure memory for persistent monitoring knowledge
    memory_config = AgentCoreMemoryConfig(
        memory_id=MEMORY_ID,
        session_id=session_id,
        actor_id=actor_id,
        retrieval_config={
            f"/ai_usage/{actor_id}/developer_metrics": RetrievalConfig(top_k=10, relevance_score=0.7),
            f"/ai_usage/{actor_id}/business_metrics": RetrievalConfig(top_k=10, relevance_score=0.7),
            f"/ai_usage/{actor_id}/compliance_data": RetrievalConfig(top_k=5, relevance_score=0.8),
            f"/ai_usage/{actor_id}/security_events": RetrievalConfig(top_k=8, relevance_score=0.8),
            f"/ai_usage/{actor_id}/productivity_data": RetrievalConfig(top_k=7, relevance_score=0.6),
            f"/ai_usage/{actor_id}/cost_data": RetrievalConfig(top_k=5, relevance_score=0.7),
            f"/ai_usage/{actor_id}/policy_violations": RetrievalConfig(top_k=5, relevance_score=0.8)
        }
    )
    
    # Initialize orchestrator
    orchestrator = AIUsageMonitoringOrchestrator(session_id, memory_config)
    
    # Parse request
    monitoring_type = payload.get('monitoring_type', 'general')
    query = payload.get('query', '')
    data = payload.get('data', {})
    
    # Route to appropriate monitoring agent
    if monitoring_type == 'developer_monitoring':
        result = orchestrator.developer_monitoring_agent(
            f"Developer AI Usage Analysis: {query}\nData: {data}"
        )
    elif monitoring_type == 'business_user_monitoring':
        result = orchestrator.business_user_monitoring_agent(
            f"Business User AI Analysis: {query}\nData: {data}"
        )
    elif monitoring_type == 'compliance_monitoring':
        result = orchestrator.compliance_monitoring_agent(
            f"Compliance Monitoring: {query}\nData: {data}"
        )
    elif monitoring_type == 'security_monitoring':
        result = orchestrator.security_monitoring_agent(
            f"Security Analysis: {query}\nData: {data}"
        )
    elif monitoring_type == 'productivity_analytics':
        result = orchestrator.productivity_analytics_agent(
            f"Productivity Analysis: {query}\nData: {data}"
        )
    elif monitoring_type == 'cost_optimization':
        result = orchestrator.cost_optimization_agent(
            f"Cost Analysis: {query}\nData: {data}"
        )
    elif monitoring_type == 'policy_enforcement':
        result = orchestrator.policy_enforcement_agent(
            f"Policy Enforcement: {query}\nData: {data}"
        )
    elif monitoring_type == 'mcp_monitoring':
        result = orchestrator.mcp_monitoring_agent(
            f"MCP Monitoring: {query}\nData: {data}"
        )
    else:
        # General monitoring - route to most appropriate agent based on query
        result = orchestrator._route_general_monitoring_query(query, data)
    
    return {
        "response": result.message.get('content', [{}])[0].get('text', str(result)),
        "session_id": session_id,
        "monitoring_type": monitoring_type,
        "timestamp": payload.get('timestamp', '')
    }

if __name__ == "__main__":
    app.run()
    def _create_mcp_monitoring_agent(self) -> Agent:
        """Agent for monitoring Model Context Protocol (MCP) usage and security"""
        return Agent(
            model=MODEL_ID,
            session_manager=self.session_manager,
            system_prompt="""You are an MCP (Model Context Protocol) Monitoring Specialist with enterprise integration. Your role is to:

1. MCP PROTOCOL MONITORING (Sumo Logic Integration):
   - Monitor MCP server-client communications and log to Sumo Logic with structured data
   - Track MCP tool invocations, resource access, and prompt executions
   - Analyze MCP message patterns for security risks and policy violations
   - Generate real-time MCP usage analytics and compliance dashboards

2. MCP SERVER SECURITY (Rapid7 Integration):
   - Monitor MCP server configurations for security vulnerabilities
   - Detect unauthorized MCP server deployments and shadow MCP usage
   - Track MCP server process health, performance, and availability
   - Correlate MCP security events with Rapid7 threat intelligence

3. MCP COMPLIANCE MANAGEMENT (Jira Integration):
   - Ensure MCP server approvals and authorization workflows through Jira
   - Monitor MCP tool usage against organizational policies
   - Track MCP configuration changes and security reviews
   - Generate compliance violations and remediation tickets in Jira

4. MCP USAGE ANALYTICS:
   - Analyze MCP tool usage patterns and user behavior
   - Monitor MCP server performance and resource utilization
   - Track MCP client adoption and usage trends across departments
   - Identify high-risk MCP operations and sensitive data exposure

5. MCP SECURITY CONTROLS:
   - Implement MCP message interception and analysis
   - Monitor MCP authentication and authorization patterns
   - Detect MCP-based data exfiltration and policy violations
   - Coordinate MCP incident response across security platforms

6. ENTERPRISE MCP GOVERNANCE:
   - Maintain MCP server registry and approval workflows
   - Monitor MCP configuration files and deployment changes
   - Track MCP client registrations and access controls
   - Generate MCP compliance reports for audit and regulatory requirements

Use advanced MCP protocol analysis to detect security risks and policy violations.
Provide comprehensive MCP governance with full enterprise tool integration.""",
            tools=[self.code_interpreter.code_interpreter]
        )