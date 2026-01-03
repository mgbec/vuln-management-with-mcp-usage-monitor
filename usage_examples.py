"""
Usage Examples for Vulnerability Management System
Demonstrates how to interact with each specialized agent
"""

# Example 1: Asset Discovery - Addressing Incomplete Asset Visibility
asset_discovery_request = {
    "request_type": "asset_discovery",
    "query": "Analyze our current asset inventory and identify blind spots",
    "data": {
        "network_scans": "scan_results.json",
        "cloud_inventory": "aws_assets.json",
        "cmdb_export": "cmdb_data.csv"
    },
    "actor_id": "security-team"
}

# Example 2: Risk Prioritization - Addressing Overwhelming Volume
risk_prioritization_request = {
    "request_type": "risk_prioritization", 
    "query": "Prioritize these 5000 vulnerabilities based on business risk",
    "data": {
        "vulnerability_scan": "nessus_results.xml",
        "asset_criticality": "business_critical_assets.json",
        "threat_intel": "current_threats.json",
        "compensating_controls": "security_controls.yaml"
    },
    "actor_id": "security-team"
}

# Example 3: Resource Optimization - Addressing Budget Constraints
resource_optimization_request = {
    "request_type": "resource_optimization",
    "query": "Optimize our vulnerability management resources and demonstrate ROI",
    "data": {
        "current_budget": 500000,
        "team_size": 8,
        "tool_costs": "security_tools_budget.json",
        "vulnerability_metrics": "vm_metrics_q4.json"
    },
    "actor_id": "security-manager"
}

# Example 4: Collaboration - Addressing Siloed Teams
collaboration_request = {
    "request_type": "collaboration",
    "query": "Create a workflow to improve coordination between security, IT, and dev teams",
    "data": {
        "current_processes": "team_workflows.json",
        "communication_tools": ["slack", "jira", "servicenow"],
        "team_structures": "org_chart.json",
        "sla_requirements": "security_slas.yaml"
    },
    "actor_id": "security-manager"
}

# Example 5: Strategic Planning - Addressing Reactive Mindset
strategic_planning_request = {
    "request_type": "strategic_planning",
    "query": "Develop a 3-year strategic plan to mature our vulnerability management program",
    "data": {
        "current_maturity": "level_2_reactive",
        "business_objectives": "company_strategy.json",
        "industry_benchmarks": "security_benchmarks.json",
        "budget_projections": "3year_budget.json"
    },
    "actor_id": "ciso"
}

# Example 6: Legacy Systems - Addressing Technical Debt
legacy_systems_request = {
    "request_type": "legacy_systems",
    "query": "Create a risk mitigation plan for our legacy Windows Server 2012 systems",
    "data": {
        "legacy_inventory": "legacy_systems.json",
        "business_dependencies": "system_dependencies.json",
        "vulnerability_data": "legacy_vulns.json",
        "modernization_budget": 200000
    },
    "actor_id": "infrastructure-team"
}

# Example 7: Patch Management - Addressing Deployment Delays
patch_management_request = {
    "request_type": "patch_management",
    "query": "Design an automated patch management process for our complex environment",
    "data": {
        "environment_topology": "network_diagram.json",
        "system_dependencies": "dependency_map.json",
        "maintenance_windows": "maintenance_schedule.json",
        "testing_requirements": "patch_testing_matrix.json"
    },
    "actor_id": "operations-team"
}

# Example 8: General Query - Multi-agent coordination
general_request = {
    "request_type": "general",
    "query": "We just discovered a critical zero-day affecting our web servers. What's our complete response plan?",
    "data": {
        "affected_systems": "web_server_inventory.json",
        "vulnerability_details": "zero_day_advisory.json",
        "business_impact": "web_services_criticality.json"
    },
    "actor_id": "incident-response-team"
}

# Example API calls (using agentcore CLI or direct invocation)
"""
# Asset Discovery
agentcore invoke '{"request_type": "asset_discovery", "query": "Scan for shadow IT in our AWS environment", "data": {"aws_accounts": ["123456789", "987654321"]}, "actor_id": "security-team"}'

# Risk Prioritization  
agentcore invoke '{"request_type": "risk_prioritization", "query": "Prioritize vulnerabilities for Q1 patching cycle", "data": {"scan_results": "q1_scan.json"}, "actor_id": "security-team"}'

# Resource Optimization
agentcore invoke '{"request_type": "resource_optimization", "query": "Calculate ROI for additional security analyst", "data": {"current_metrics": "vm_kpis.json"}, "actor_id": "security-manager"}'
"""