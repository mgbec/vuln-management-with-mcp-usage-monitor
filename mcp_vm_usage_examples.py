"""
MCP-VM Integration Usage Examples
Practical examples showing how MCP monitoring integrates with vulnerability management
"""

import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any

# Import the integration components
from mcp_vulnerability_bridge import MCPVulnerabilityManager, MCPVulnerabilityEvent, MCPUsageEvent
from sumo_rapid7_jira_integrations import AIMonitoringWorkflowOrchestrator

class MCPVMUsageExamples:
    """Comprehensive usage examples for MCP-VM integration"""
    
    def __init__(self):
        # Initialize the integrated system
        self.monitoring_orchestrator = AIMonitoringWorkflowOrchestrator(
            sumo_config={
                'sumo_endpoint': 'https://collectors.sumologic.com/receiver/v1/http/your-endpoint',
                'access_id': 'your-access-id',
                'access_key': 'your-access-key'
            },
            rapid7_config={
                'rapid7_api_key': 'your-rapid7-api-key',
                'region': 'us'
            },
            jira_config={
                'jira_url': 'https://your-company.atlassian.net',
                'username': 'your-email@company.com',
                'api_token': 'your-jira-api-token',
                'project_key': 'MCPSEC'
            }
        )
        
        self.mcp_vm_manager = MCPVulnerabilityManager(
            vm_system_endpoint='https://your-vm-system.amazonaws.com',
            monitoring_orchestrator=self.monitoring_orchestrator
        )
    
    def example_1_command_injection_detection(self):
        """Example 1: Detecting command injection in MCP tool usage"""
        
        print("=== Example 1: Command Injection Detection ===")
        
        # Simulate MCP event with command injection attempt
        mcp_event = MCPUsageEvent(
            timestamp=datetime.utcnow().isoformat(),
            session_id='session_cmd_injection_001',
            user_id='suspicious.user@company.com',
            client_name='custom-mcp-client',
            server_name='filesystem-server',
            method='tools/call',
            tool_name='execute_command',
            request_size=512,
            response_size=0,  # Failed execution
            execution_time_ms=50.0,
            success=False,
            error_message='Command execution failed',
            sensitive_data_detected=False,
            risk_level='high',
            compliance_tags=['command_execution'],
            source_ip='192.168.1.150',
            user_agent='Custom MCP Client/1.0'
        )
        
        # The MCP message would contain something like:
        # {"method": "tools/call", "params": {"name": "execute_command", "arguments": {"command": "ls -la; rm -rf /important/data"}}}
        
        print(f"Simulating MCP event: {mcp_event.tool_name} by {mcp_event.user_id}")
        
        # Analyze for vulnerabilities
        vulnerability_event = self.mcp_vm_manager.mcp_analyzer.analyze_mcp_usage_event(mcp_event)
        
        if vulnerability_event:
            print(f"✅ Command injection detected!")
            print(f"   Vulnerability Type: {vulnerability_event.vulnerability_type}")
            print(f"   Severity: {vulnerability_event.severity}")
            print(f"   Risk Score: {vulnerability_event.risk_score}")
            print(f"   Compliance Impact: {vulnerability_event.compliance_impact}")
            
            # This would trigger the full VM workflow:
            # 1. Risk prioritization based on user, server, and tool context
            # 2. Security incident creation in Rapid7
            # 3. Jira ticket for remediation
            # 4. Sumo Logic logging for analytics
            
            return vulnerability_event
        else:
            print("❌ No vulnerability detected")
            return None
    
    def example_2_credential_exposure_workflow(self):
        """Example 2: Complete workflow for credential exposure in MCP communication"""
        
        print("\n=== Example 2: Credential Exposure Workflow ===")
        
        # Simulate MCP event with credential exposure
        mcp_event = MCPUsageEvent(
            timestamp=datetime.utcnow().isoformat(),
            session_id='session_cred_exposure_002',
            user_id='developer@company.com',
            client_name='claude-desktop',
            server_name='database-server',
            method='tools/call',
            tool_name='database_query',
            request_size=1024,
            response_size=2048,
            execution_time_ms=250.0,
            success=True,
            error_message=None,
            sensitive_data_detected=True,  # Detected by MCP monitor
            risk_level='high',
            compliance_tags=['database_access', 'sensitive_data'],
            source_ip='10.0.1.45',
            user_agent='Claude Desktop/1.0.0'
        )
        
        # The MCP message contained: {"query": "SELECT * FROM users WHERE password='admin123'"}
        
        print(f"Processing credential exposure event from {mcp_event.user_id}")
        
        # Analyze vulnerability
        vulnerability_event = self.mcp_vm_manager.mcp_analyzer.analyze_mcp_usage_event(mcp_event)
        
        if vulnerability_event:
            print(f"🚨 Credential exposure detected!")
            
            # Process through complete VM workflow
            print("Initiating integrated response workflow...")
            
            # 1. VM Risk Prioritization
            print("  Step 1: Risk prioritization through VM system")
            vm_payload = {
                'request_type': 'risk_prioritization',
                'query': f'Prioritize MCP credential exposure vulnerability',
                'data': {
                    'vulnerabilities': [{
                        'vulnerability_id': vulnerability_event.event_id,
                        'title': 'MCP Credential Exposure',
                        'severity': vulnerability_event.severity,
                        'affected_assets': vulnerability_event.affected_assets,
                        'user_context': {
                            'user_id': vulnerability_event.user_id,
                            'mcp_server': vulnerability_event.mcp_server,
                            'mcp_tool': vulnerability_event.mcp_tool
                        }
                    }]
                },
                'actor_id': 'mcp-security-team'
            }
            
            # 2. Security Incident Creation
            print("  Step 2: Creating security incident")
            incident_data = {
                'severity': 'high',
                'user_id': vulnerability_event.user_id,
                'violation_type': 'credential_exposure',
                'ai_tool': f'MCP:{vulnerability_event.mcp_server}',
                'sensitive_data_types': ['credentials'],
                'risk_score': int(vulnerability_event.risk_score),
                'source_ip': '10.0.1.45',
                'department': 'Engineering',
                'sensitive_data_detected': True,
                'policy_violations': ['credential_exposure', 'sensitive_data_handling'],
                'timestamp': vulnerability_event.timestamp
            }
            
            # Process through monitoring orchestrator
            result = self.monitoring_orchestrator.process_ai_security_incident(incident_data)
            
            print(f"  ✅ Workflow completed: {result['workflow_status']}")
            if result.get('jira_ticket'):
                print(f"     Jira ticket created: {result['jira_ticket'].get('key', 'N/A')}")
            if result.get('rapid7_investigation'):
                print(f"     Rapid7 investigation: {result['rapid7_investigation'].get('id', 'N/A')}")
            
            return result
        
        return None
    
    def example_3_mcp_server_vulnerability_management(self):
        """Example 3: Managing vulnerabilities in MCP servers themselves"""
        
        print("\n=== Example 3: MCP Server Vulnerability Management ===")
        
        # Simulate discovery of vulnerability in MCP server software
        server_vulnerability = {
            'server_name': 'filesystem-server',
            'vulnerability_id': 'MCP-FS-2024-001',
            'cve_id': 'CVE-2024-12345',
            'severity': 'critical',
            'description': 'Path traversal vulnerability in filesystem server allowing arbitrary file access',
            'affected_versions': '1.0.0 - 1.2.3',
            'patch_available': True,
            'patch_version': '1.2.4',
            'discovered_date': datetime.utcnow().isoformat()
        }
        
        print(f"Processing server vulnerability: {server_vulnerability['cve_id']}")
        
        # Store server vulnerability
        import sqlite3
        conn = sqlite3.connect(self.mcp_vm_manager.mcp_analyzer.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO mcp_server_vulnerabilities 
            (server_name, vulnerability_id, cve_id, severity, description, 
             affected_versions, patch_available, patch_version, discovered_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            server_vulnerability['server_name'],
            server_vulnerability['vulnerability_id'],
            server_vulnerability['cve_id'],
            server_vulnerability['severity'],
            server_vulnerability['description'],
            server_vulnerability['affected_versions'],
            server_vulnerability['patch_available'],
            server_vulnerability['patch_version'],
            server_vulnerability['discovered_date']
        ))
        
        conn.commit()
        conn.close()
        
        print("✅ Server vulnerability registered")
        
        # Now any MCP usage of this server will be flagged as high-risk
        # Simulate MCP usage on vulnerable server
        mcp_event = MCPUsageEvent(
            timestamp=datetime.utcnow().isoformat(),
            session_id='session_vuln_server_003',
            user_id='normal.user@company.com',
            client_name='claude-desktop',
            server_name='filesystem-server',  # Vulnerable server
            method='tools/call',
            tool_name='read_file',
            request_size=256,
            response_size=1024,
            execution_time_ms=100.0,
            success=True,
            error_message=None,
            sensitive_data_detected=False,
            risk_level='medium',
            compliance_tags=['file_access'],
            source_ip='192.168.1.100',
            user_agent='Claude Desktop/1.0.0'
        )
        
        # Analyze - should detect server vulnerability
        vulnerability_event = self.mcp_vm_manager.mcp_analyzer.analyze_mcp_usage_event(mcp_event)
        
        if vulnerability_event:
            print(f"🚨 Usage of vulnerable server detected!")
            print(f"   Server: {vulnerability_event.mcp_server}")
            print(f"   Vulnerability: {vulnerability_event.vulnerability_type}")
            print(f"   Risk Score: {vulnerability_event.risk_score}")
            
            # This would trigger patch management workflow
            print("  Triggering patch management workflow...")
            
            patch_recommendation = {
                'server_name': server_vulnerability['server_name'],
                'current_version': '1.2.3',
                'target_version': server_vulnerability['patch_version'],
                'patch_priority': 'critical',
                'estimated_downtime': '15 minutes',
                'rollback_plan': 'Automated rollback to previous version',
                'validation_steps': [
                    'Verify MCP server starts successfully',
                    'Test basic tool functionality',
                    'Confirm vulnerability is patched'
                ]
            }
            
            print(f"  📋 Patch recommendation generated:")
            print(f"     Update {patch_recommendation['server_name']} to {patch_recommendation['target_version']}")
            print(f"     Priority: {patch_recommendation['patch_priority']}")
            print(f"     Downtime: {patch_recommendation['estimated_downtime']}")
            
            return patch_recommendation
        
        return None
    
    def example_4_compliance_monitoring_integration(self):
        """Example 4: MCP compliance monitoring integrated with VM compliance"""
        
        print("\n=== Example 4: Compliance Monitoring Integration ===")
        
        # Simulate MCP usage that violates compliance policies
        compliance_violation_events = [
            {
                'event': MCPUsageEvent(
                    timestamp=datetime.utcnow().isoformat(),
                    session_id='session_compliance_001',
                    user_id='finance.user@company.com',
                    client_name='excel-copilot',
                    server_name='database-server',
                    method='tools/call',
                    tool_name='financial_query',
                    request_size=512,
                    response_size=4096,
                    execution_time_ms=300.0,
                    success=True,
                    error_message=None,
                    sensitive_data_detected=True,
                    risk_level='high',
                    compliance_tags=['financial_data', 'sox_relevant'],
                    source_ip='10.0.2.25',
                    user_agent='Excel Copilot/1.0'
                ),
                'violation_type': 'sox_financial_data_access',
                'compliance_framework': 'SOX'
            },
            {
                'event': MCPUsageEvent(
                    timestamp=datetime.utcnow().isoformat(),
                    session_id='session_compliance_002',
                    user_id='hr.user@company.com',
                    client_name='hr-assistant',
                    server_name='hr-database-server',
                    method='tools/call',
                    tool_name='employee_lookup',
                    request_size=256,
                    response_size=2048,
                    execution_time_ms=150.0,
                    success=True,
                    error_message=None,
                    sensitive_data_detected=True,
                    risk_level='medium',
                    compliance_tags=['pii_data', 'gdpr_relevant'],
                    source_ip='10.0.3.15',
                    user_agent='HR Assistant/2.0'
                ),
                'violation_type': 'gdpr_pii_processing',
                'compliance_framework': 'GDPR'
            }
        ]
        
        compliance_results = []
        
        for violation in compliance_violation_events:
            mcp_event = violation['event']
            
            print(f"Processing compliance event: {violation['compliance_framework']} - {mcp_event.user_id}")
            
            # Analyze for compliance violations
            vulnerability_event = self.mcp_vm_manager.mcp_analyzer.analyze_mcp_usage_event(mcp_event)
            
            if vulnerability_event:
                print(f"  🚨 Compliance violation detected: {violation['violation_type']}")
                
                # Create compliance violation through monitoring orchestrator
                compliance_data = {
                    'violation_type': violation['violation_type'],
                    'user_id': mcp_event.user_id,
                    'department': 'Finance' if 'finance' in mcp_event.user_id else 'HR',
                    'ai_tool': f'MCP:{mcp_event.server_name}',
                    'risk_level': vulnerability_event.severity,
                    'detection_time': vulnerability_event.timestamp,
                    'compliance_frameworks': [violation['compliance_framework']],
                    'sensitive_data_types': ['financial_data'] if 'sox' in violation['violation_type'] else ['pii'],
                    'business_impact': 'High - Regulatory compliance risk',
                    'immediate_actions': [
                        'Review user access permissions',
                        'Audit data handling procedures',
                        'Implement additional controls'
                    ],
                    'content_hash': f"hash_{vulnerability_event.event_id}",
                    'source_ip': mcp_event.source_ip,
                    'priority': 'high'
                }
                
                # Process compliance violation
                result = self.monitoring_orchestrator.process_compliance_violation(compliance_data)
                
                print(f"  ✅ Compliance workflow completed: {result['workflow_status']}")
                if result.get('jira_ticket'):
                    print(f"     Compliance ticket: {result['jira_ticket'].get('key', 'N/A')}")
                
                compliance_results.append(result)
        
        # Generate compliance summary
        print(f"\n📊 Compliance Summary:")
        print(f"   Total violations processed: {len(compliance_results)}")
        print(f"   Successful workflows: {sum(1 for r in compliance_results if r['workflow_status'] == 'success')}")
        print(f"   Frameworks affected: SOX, GDPR")
        
        return compliance_results
    
    def example_5_strategic_mcp_security_planning(self):
        """Example 5: Strategic security planning incorporating MCP risks"""
        
        print("\n=== Example 5: Strategic MCP Security Planning ===")
        
        # Generate MCP security metrics for strategic planning
        from mcp_vulnerability_bridge import MCPVulnerabilityReporter
        
        reporter = MCPVulnerabilityReporter()
        
        # Generate report for last 30 days
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=30)
        
        mcp_report = reporter.generate_mcp_vulnerability_report(
            start_date.isoformat(),
            end_date.isoformat()
        )
        
        print("📈 MCP Security Metrics (Last 30 Days):")
        print(f"   Total MCP vulnerabilities: {mcp_report['summary']['total_mcp_vulnerabilities']}")
        print(f"   Critical vulnerabilities: {mcp_report['summary']['critical_vulnerabilities']}")
        print(f"   Affected servers: {mcp_report['summary']['affected_servers']}")
        print(f"   Average risk score: {mcp_report['summary']['avg_risk_score']:.2f}")
        
        # Strategic recommendations based on MCP analysis
        strategic_recommendations = {
            'immediate_actions': [
                'Implement MCP message content filtering',
                'Enhance MCP server approval processes',
                'Deploy automated MCP vulnerability scanning'
            ],
            'short_term_goals': [
                'Integrate MCP monitoring with existing SIEM',
                'Develop MCP-specific incident response procedures',
                'Create MCP security training program'
            ],
            'long_term_strategy': [
                'Establish MCP Center of Excellence',
                'Develop organizational MCP governance framework',
                'Implement zero-trust architecture for MCP communications'
            ],
            'budget_requirements': {
                'mcp_security_tools': 150000,
                'training_and_certification': 50000,
                'additional_security_staff': 200000,
                'infrastructure_upgrades': 100000
            }
        }
        
        print(f"\n🎯 Strategic Recommendations:")
        for category, items in strategic_recommendations.items():
            if category != 'budget_requirements':
                print(f"   {category.replace('_', ' ').title()}:")
                for item in items:
                    print(f"     • {item}")
        
        print(f"\n💰 Budget Requirements:")
        total_budget = 0
        for item, cost in strategic_recommendations['budget_requirements'].items():
            print(f"   {item.replace('_', ' ').title()}: ${cost:,}")
            total_budget += cost
        print(f"   Total Annual Budget: ${total_budget:,}")
        
        return {
            'mcp_metrics': mcp_report,
            'strategic_plan': strategic_recommendations
        }
    
    def run_all_examples(self):
        """Run all integration examples"""
        
        print("🚀 Running MCP-VM Integration Examples")
        print("=" * 50)
        
        results = {}
        
        # Example 1: Command Injection
        results['command_injection'] = self.example_1_command_injection_detection()
        
        # Example 2: Credential Exposure Workflow
        results['credential_exposure'] = self.example_2_credential_exposure_workflow()
        
        # Example 3: Server Vulnerability Management
        results['server_vulnerability'] = self.example_3_mcp_server_vulnerability_management()
        
        # Example 4: Compliance Integration
        results['compliance_monitoring'] = self.example_4_compliance_monitoring_integration()
        
        # Example 5: Strategic Planning
        results['strategic_planning'] = self.example_5_strategic_mcp_security_planning()
        
        print("\n" + "=" * 50)
        print("🎉 All examples completed successfully!")
        
        return results

# Usage
if __name__ == "__main__":
    # Initialize and run examples
    examples = MCPVMUsageExamples()
    
    # Run individual example
    print("Running individual example...")
    vulnerability_event = examples.example_1_command_injection_detection()
    
    if vulnerability_event:
        print(f"\nDetected vulnerability details:")
        print(f"Event ID: {vulnerability_event.event_id}")
        print(f"Type: {vulnerability_event.vulnerability_type}")
        print(f"Severity: {vulnerability_event.severity}")
        print(f"Risk Score: {vulnerability_event.risk_score}")
    
    # Uncomment to run all examples
    # results = examples.run_all_examples()
    # print(f"\nExample results summary: {len(results)} scenarios processed")