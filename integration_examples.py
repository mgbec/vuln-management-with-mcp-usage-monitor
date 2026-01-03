"""
Practical Integration Examples for VM AgentCore System
Real-world connectors and data processors
"""

import json
import requests
import pandas as pd
import boto3
from typing import Dict, List, Any
import xml.etree.ElementTree as ET

class VulnerabilityDataProcessor:
    """Handles data ingestion from various vulnerability sources"""
    
    def __init__(self, vm_system_endpoint: str):
        self.vm_endpoint = vm_system_endpoint
    
    def process_nessus_scan(self, nessus_file: str) -> Dict:
        """Process Nessus .nessus XML file"""
        tree = ET.parse(nessus_file)
        root = tree.getroot()
        
        vulnerabilities = []
        for host in root.findall('.//ReportHost'):
            host_ip = host.get('name')
            
            for item in host.findall('.//ReportItem'):
                vuln = {
                    'host': host_ip,
                    'plugin_id': item.get('pluginID'),
                    'plugin_name': item.get('pluginName'),
                    'severity': item.get('severity'),
                    'cve': [cve.text for cve in item.findall('.//cve')],
                    'cvss_score': item.findtext('.//cvss_base_score', '0'),
                    'description': item.findtext('.//description', ''),
                    'solution': item.findtext('.//solution', '')
                }
                vulnerabilities.append(vuln)
        
        # Send to VM system for prioritization
        payload = {
            "request_type": "risk_prioritization",
            "query": f"Prioritize {len(vulnerabilities)} vulnerabilities from Nessus scan",
            "data": {
                "scan_type": "nessus",
                "vulnerabilities": vulnerabilities,
                "scan_date": "2024-01-03"
            }
        }
        
        return self._call_vm_system(payload)
    
    def process_qualys_api(self, api_credentials: Dict) -> Dict:
        """Process Qualys VMDR API data"""
        # Authenticate with Qualys
        auth_url = f"https://{api_credentials['server']}/api/2.0/fo/session/"
        auth_data = {
            'action': 'login',
            'username': api_credentials['username'],
            'password': api_credentials['password']
        }
        
        session = requests.Session()
        session.post(auth_url, data=auth_data)
        
        # Get vulnerability data
        vuln_url = f"https://{api_credentials['server']}/api/2.0/fo/asset/host/vm/detection/"
        vuln_params = {
            'action': 'list',
            'show_tags': '1',
            'details': 'All'
        }
        
        response = session.get(vuln_url, params=vuln_params)
        
        # Parse XML response (simplified)
        vulnerabilities = self._parse_qualys_xml(response.text)
        
        payload = {
            "request_type": "risk_prioritization", 
            "query": f"Analyze Qualys vulnerabilities for {len(vulnerabilities)} hosts",
            "data": {
                "scan_type": "qualys",
                "vulnerabilities": vulnerabilities,
                "api_source": True
            }
        }
        
        return self._call_vm_system(payload)
    
    def process_aws_inspector(self, aws_region: str) -> Dict:
        """Process AWS Inspector findings"""
        inspector = boto3.client('inspector2', region_name=aws_region)
        
        # Get findings
        response = inspector.list_findings(
            filterCriteria={
                'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]
            }
        )
        
        findings = []
        for finding in response['findings']:
            vuln = {
                'finding_arn': finding['findingArn'],
                'severity': finding['severity'],
                'title': finding['title'],
                'description': finding['description'],
                'resource_id': finding['resources'][0]['id'],
                'resource_type': finding['resources'][0]['type'],
                'package_vulnerability_details': finding.get('packageVulnerabilityDetails', {}),
                'network_reachability': finding.get('networkReachabilityDetails', {})
            }
            findings.append(vuln)
        
        payload = {
            "request_type": "risk_prioritization",
            "query": f"Prioritize {len(findings)} AWS Inspector findings",
            "data": {
                "scan_type": "aws_inspector",
                "findings": findings,
                "aws_region": aws_region
            }
        }
        
        return self._call_vm_system(payload)
    
    def _parse_qualys_xml(self, xml_data: str) -> List[Dict]:
        """Parse Qualys XML response"""
        # Simplified XML parsing - implement based on actual Qualys format
        return []
    
    def _call_vm_system(self, payload: Dict) -> Dict:
        """Call the VM AgentCore system"""
        response = requests.post(
            f"{self.vm_endpoint}/invoke",
            json=payload,
            headers={'Content-Type': 'application/json'}
        )
        return response.json()

class AssetDiscoveryIntegrator:
    """Integrates with various asset discovery sources"""
    
    def __init__(self, vm_system_endpoint: str):
        self.vm_endpoint = vm_system_endpoint
    
    def discover_aws_assets(self, aws_accounts: List[str]) -> Dict:
        """Discover AWS assets across multiple accounts"""
        all_assets = []
        
        for account_id in aws_accounts:
            # Use AWS Config to get resources
            config_client = boto3.client('config')
            
            # Get EC2 instances
            ec2_resources = config_client.list_discovered_resources(
                resourceType='AWS::EC2::Instance'
            )
            
            for resource in ec2_resources['resourceIdentifiers']:
                asset = {
                    'account_id': account_id,
                    'resource_type': 'EC2Instance',
                    'resource_id': resource['resourceId'],
                    'region': resource.get('region', 'unknown'),
                    'discovery_method': 'aws_config'
                }
                all_assets.append(asset)
            
            # Get RDS instances
            rds_resources = config_client.list_discovered_resources(
                resourceType='AWS::RDS::DBInstance'
            )
            
            for resource in rds_resources['resourceIdentifiers']:
                asset = {
                    'account_id': account_id,
                    'resource_type': 'RDSInstance',
                    'resource_id': resource['resourceId'],
                    'region': resource.get('region', 'unknown'),
                    'discovery_method': 'aws_config'
                }
                all_assets.append(asset)
        
        payload = {
            "request_type": "asset_discovery",
            "query": f"Process {len(all_assets)} AWS assets across {len(aws_accounts)} accounts",
            "data": {
                "assets": all_assets,
                "discovery_type": "aws_multi_account",
                "accounts": aws_accounts
            }
        }
        
        return self._call_vm_system(payload)
    
    def discover_network_assets(self, network_ranges: List[str]) -> Dict:
        """Discover assets via network scanning"""
        import nmap
        
        nm = nmap.PortScanner()
        discovered_assets = []
        
        for network_range in network_ranges:
            # Perform network scan
            scan_result = nm.scan(hosts=network_range, arguments='-sn')  # Ping scan
            
            for host in scan_result['scan']:
                if scan_result['scan'][host]['status']['state'] == 'up':
                    asset = {
                        'ip_address': host,
                        'hostname': scan_result['scan'][host].get('hostnames', [{}])[0].get('name', ''),
                        'mac_address': scan_result['scan'][host].get('addresses', {}).get('mac', ''),
                        'discovery_method': 'network_scan',
                        'network_range': network_range
                    }
                    discovered_assets.append(asset)
        
        payload = {
            "request_type": "asset_discovery",
            "query": f"Process {len(discovered_assets)} network-discovered assets",
            "data": {
                "assets": discovered_assets,
                "discovery_type": "network_scan",
                "scan_ranges": network_ranges
            }
        }
        
        return self._call_vm_system(payload)
    
    def integrate_cmdb_data(self, cmdb_export_file: str) -> Dict:
        """Integrate CMDB data (ServiceNow, etc.)"""
        # Read CMDB export (CSV format)
        df = pd.read_csv(cmdb_export_file)
        
        assets = []
        for _, row in df.iterrows():
            asset = {
                'ci_name': row.get('name', ''),
                'ci_class': row.get('sys_class_name', ''),
                'ip_address': row.get('ip_address', ''),
                'location': row.get('location', ''),
                'business_service': row.get('business_service', ''),
                'owner': row.get('owned_by', ''),
                'criticality': row.get('business_criticality', 'medium'),
                'discovery_method': 'cmdb_import'
            }
            assets.append(asset)
        
        payload = {
            "request_type": "asset_discovery",
            "query": f"Process {len(assets)} CMDB assets",
            "data": {
                "assets": assets,
                "discovery_type": "cmdb_import",
                "source_file": cmdb_export_file
            }
        }
        
        return self._call_vm_system(payload)
    
    def _call_vm_system(self, payload: Dict) -> Dict:
        """Call the VM AgentCore system"""
        response = requests.post(
            f"{self.vm_endpoint}/invoke",
            json=payload,
            headers={'Content-Type': 'application/json'}
        )
        return response.json()

class TicketingIntegration:
    """Integrates with ticketing systems for automated workflow"""
    
    def __init__(self, vm_system_endpoint: str):
        self.vm_endpoint = vm_system_endpoint
    
    def create_jira_tickets(self, prioritized_vulnerabilities: List[Dict]) -> List[str]:
        """Create Jira tickets for prioritized vulnerabilities"""
        from jira import JIRA
        
        jira = JIRA(
            server='https://company.atlassian.net',
            basic_auth=('username', 'api_token')
        )
        
        created_tickets = []
        
        for vuln in prioritized_vulnerabilities:
            # Create ticket based on vulnerability priority
            issue_dict = {
                'project': {'key': 'SEC'},
                'summary': f"Vulnerability: {vuln['title']} - {vuln['affected_asset']}",
                'description': f"""
                Vulnerability Details:
                - CVE: {vuln.get('cve', 'N/A')}
                - CVSS Score: {vuln.get('cvss_score', 'N/A')}
                - Risk Score: {vuln.get('risk_score', 'N/A')}
                - Affected Asset: {vuln['affected_asset']}
                
                Recommended Actions:
                {vuln.get('remediation_steps', 'See vulnerability details')}
                
                Business Impact:
                {vuln.get('business_impact', 'To be assessed')}
                """,
                'issuetype': {'name': 'Task'},
                'priority': {'name': self._map_priority(vuln.get('priority', 'medium'))},
                'assignee': {'name': self._determine_assignee(vuln)}
            }
            
            new_issue = jira.create_issue(fields=issue_dict)
            created_tickets.append(new_issue.key)
        
        return created_tickets
    
    def create_servicenow_incidents(self, critical_vulnerabilities: List[Dict]) -> List[str]:
        """Create ServiceNow incidents for critical vulnerabilities"""
        incident_numbers = []
        
        for vuln in critical_vulnerabilities:
            incident_data = {
                'short_description': f"Critical Vulnerability: {vuln['title']}",
                'description': f"""
                Critical vulnerability detected requiring immediate attention.
                
                Details:
                - CVE: {vuln.get('cve', 'N/A')}
                - Affected System: {vuln['affected_asset']}
                - Risk Score: {vuln.get('risk_score', 'N/A')}
                - Detection Date: {vuln.get('detection_date', 'N/A')}
                
                Immediate Actions Required:
                {vuln.get('immediate_actions', 'Assess and remediate')}
                """,
                'priority': '1',  # Critical
                'urgency': '1',   # High
                'impact': '1',    # High
                'category': 'Security',
                'subcategory': 'Vulnerability Management',
                'assignment_group': self._determine_snow_group(vuln)
            }
            
            response = requests.post(
                'https://company.service-now.com/api/now/table/incident',
                auth=('snow_user', 'snow_pass'),
                headers={'Content-Type': 'application/json'},
                json=incident_data
            )
            
            if response.status_code == 201:
                incident_numbers.append(response.json()['result']['number'])
        
        return incident_numbers
    
    def _map_priority(self, vm_priority: str) -> str:
        """Map VM system priority to Jira priority"""
        mapping = {
            'critical': 'Highest',
            'high': 'High', 
            'medium': 'Medium',
            'low': 'Low'
        }
        return mapping.get(vm_priority.lower(), 'Medium')
    
    def _determine_assignee(self, vuln: Dict) -> str:
        """Determine appropriate assignee based on vulnerability"""
        asset_type = vuln.get('asset_type', '').lower()
        
        if 'web' in asset_type or 'application' in asset_type:
            return 'dev-team-lead'
        elif 'database' in asset_type:
            return 'dba-team-lead'
        elif 'network' in asset_type:
            return 'network-team-lead'
        else:
            return 'security-team-lead'
    
    def _determine_snow_group(self, vuln: Dict) -> str:
        """Determine ServiceNow assignment group"""
        asset_type = vuln.get('asset_type', '').lower()
        
        if 'windows' in asset_type:
            return 'Windows Infrastructure Team'
        elif 'linux' in asset_type:
            return 'Linux Infrastructure Team'
        elif 'network' in asset_type:
            return 'Network Operations Team'
        else:
            return 'Security Operations Team'

class DashboardIntegration:
    """Integrates with dashboard and reporting systems"""
    
    def __init__(self, vm_system_endpoint: str):
        self.vm_endpoint = vm_system_endpoint
    
    def generate_executive_dashboard_data(self) -> Dict:
        """Generate data for executive dashboard"""
        payload = {
            "request_type": "strategic_planning",
            "query": "Generate executive dashboard metrics for current quarter",
            "data": {
                "dashboard_type": "executive",
                "time_period": "current_quarter",
                "include_trends": True
            }
        }
        
        response = requests.post(
            f"{self.vm_endpoint}/invoke",
            json=payload,
            headers={'Content-Type': 'application/json'}
        )
        
        return response.json()
    
    def update_powerbi_dataset(self, dashboard_data: Dict):
        """Update PowerBI dataset with latest metrics"""
        # PowerBI REST API integration
        powerbi_data = {
            'vulnerability_metrics': dashboard_data.get('vulnerability_metrics', {}),
            'risk_trends': dashboard_data.get('risk_trends', []),
            'remediation_progress': dashboard_data.get('remediation_progress', {}),
            'team_performance': dashboard_data.get('team_performance', {})
        }
        
        # Push to PowerBI dataset
        requests.post(
            'https://api.powerbi.com/v1.0/myorg/datasets/{dataset_id}/rows',
            headers={
                'Authorization': f'Bearer {powerbi_token}',
                'Content-Type': 'application/json'
            },
            json={'rows': [powerbi_data]}
        )
    
    def send_slack_alerts(self, critical_findings: List[Dict]):
        """Send Slack alerts for critical findings"""
        webhook_url = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
        
        for finding in critical_findings:
            message = {
                "text": f"🚨 Critical Vulnerability Alert",
                "attachments": [{
                    "color": "danger",
                    "fields": [
                        {"title": "Vulnerability", "value": finding['title'], "short": True},
                        {"title": "Affected Asset", "value": finding['affected_asset'], "short": True},
                        {"title": "Risk Score", "value": finding['risk_score'], "short": True},
                        {"title": "Action Required", "value": finding['immediate_action'], "short": False}
                    ]
                }]
            }
            
            requests.post(webhook_url, json=message)

# Usage Examples
if __name__ == "__main__":
    # Initialize integrators
    vm_endpoint = "https://your-agentcore-endpoint.amazonaws.com"
    
    vuln_processor = VulnerabilityDataProcessor(vm_endpoint)
    asset_integrator = AssetDiscoveryIntegrator(vm_endpoint)
    ticket_integrator = TicketingIntegration(vm_endpoint)
    dashboard_integrator = DashboardIntegration(vm_endpoint)
    
    # Example workflow
    print("Processing Nessus scan...")
    nessus_results = vuln_processor.process_nessus_scan("latest_scan.nessus")
    
    print("Discovering AWS assets...")
    aws_assets = asset_integrator.discover_aws_assets(["123456789", "987654321"])
    
    print("Creating tickets for critical vulnerabilities...")
    if nessus_results.get('critical_vulnerabilities'):
        tickets = ticket_integrator.create_jira_tickets(nessus_results['critical_vulnerabilities'])
        print(f"Created {len(tickets)} tickets")
    
    print("Updating executive dashboard...")
    dashboard_data = dashboard_integrator.generate_executive_dashboard_data()
    dashboard_integrator.update_powerbi_dataset(dashboard_data)