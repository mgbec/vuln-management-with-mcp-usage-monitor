"""
AI Usage Monitoring System - Sumo Logic, Rapid7, and Jira Integrations
Optimized for enterprise security and incident management workflows
"""

import json
import requests
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import base64
import hashlib
import re

class SumoLogicAIMonitoringIntegration:
    """Integration with Sumo Logic for centralized AI usage logging and analytics"""
    
    def __init__(self, sumo_endpoint: str, access_id: str, access_key: str):
        self.sumo_endpoint = sumo_endpoint
        self.access_id = access_id
        self.access_key = access_key
        self.auth_header = base64.b64encode(f"{access_id}:{access_key}".encode()).decode()
        
    def send_ai_usage_logs(self, usage_data: Dict) -> bool:
        """Send AI usage data to Sumo Logic"""
        headers = {
            'Authorization': f'Basic {self.auth_header}',
            'Content-Type': 'application/json',
            'X-Sumo-Category': 'ai_usage_monitoring',
            'X-Sumo-Name': 'ai_usage_events'
        }
        
        # Structure log data for Sumo Logic
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'ai_usage',
            'user_id': usage_data.get('user_id'),
            'department': usage_data.get('department'),
            'ai_tool': usage_data.get('tool_name'),
            'session_duration': usage_data.get('session_duration', 0),
            'content_generated': usage_data.get('content_generated', 0),
            'risk_level': usage_data.get('risk_level', 'low'),
            'compliance_status': usage_data.get('compliance_status', 'compliant'),
            'sensitive_data_detected': usage_data.get('sensitive_data_detected', False),
            'policy_violations': usage_data.get('policy_violations', []),
            'source_ip': usage_data.get('source_ip'),
            'user_agent': usage_data.get('user_agent'),
            'bytes_transferred': usage_data.get('bytes_transferred', 0)
        }
        
        try:
            response = requests.post(
                self.sumo_endpoint,
                headers=headers,
                data=json.dumps(log_entry)
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Failed to send logs to Sumo Logic: {e}")
            return False
    
    def send_security_alert(self, alert_data: Dict) -> bool:
        """Send security alerts to Sumo Logic for immediate attention"""
        headers = {
            'Authorization': f'Basic {self.auth_header}',
            'Content-Type': 'application/json',
            'X-Sumo-Category': 'security_alerts',
            'X-Sumo-Name': 'ai_security_incidents'
        }
        
        alert_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'security_alert',
            'alert_severity': alert_data.get('severity', 'medium'),
            'alert_type': 'ai_usage_violation',
            'user_id': alert_data.get('user_id'),
            'violation_type': alert_data.get('violation_type'),
            'ai_tool': alert_data.get('ai_tool'),
            'sensitive_data_types': alert_data.get('sensitive_data_types', []),
            'risk_score': alert_data.get('risk_score', 0),
            'remediation_required': alert_data.get('remediation_required', True),
            'source_ip': alert_data.get('source_ip'),
            'detection_method': alert_data.get('detection_method'),
            'raw_content_hash': alert_data.get('content_hash')  # Hash only, not actual content
        }
        
        try:
            response = requests.post(
                self.sumo_endpoint,
                headers=headers,
                data=json.dumps(alert_entry)
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Failed to send security alert to Sumo Logic: {e}")
            return False
    
    def query_ai_usage_analytics(self, query: str, start_time: str, end_time: str) -> Dict:
        """Query Sumo Logic for AI usage analytics"""
        search_url = f"https://api.sumologic.com/api/v1/search/jobs"
        
        headers = {
            'Authorization': f'Basic {self.auth_header}',
            'Content-Type': 'application/json'
        }
        
        search_job = {
            'query': query,
            'from': start_time,
            'to': end_time,
            'timeZone': 'UTC'
        }
        
        try:
            # Start search job
            response = requests.post(search_url, headers=headers, json=search_job)
            
            if response.status_code == 202:
                job_id = response.json()['id']
                
                # Poll for results
                results_url = f"https://api.sumologic.com/api/v1/search/jobs/{job_id}/records"
                
                # Wait for job completion (simplified polling)
                import time
                time.sleep(5)
                
                results_response = requests.get(results_url, headers=headers)
                
                if results_response.status_code == 200:
                    return results_response.json()
            
            return {'error': 'Failed to execute query'}
        except Exception as e:
            return {'error': f'Query failed: {e}'}
    
    def create_ai_usage_dashboard(self) -> Dict:
        """Create Sumo Logic dashboard for AI usage monitoring"""
        dashboard_config = {
            'title': 'AI Usage Monitoring Dashboard',
            'description': 'Comprehensive AI tool usage and security monitoring',
            'panels': [
                {
                    'title': 'AI Tool Usage by Department',
                    'query': '_sourceCategory=ai_usage_monitoring | json field=department | count by department',
                    'visualization': 'pie_chart'
                },
                {
                    'title': 'High Risk AI Activities',
                    'query': '_sourceCategory=ai_usage_monitoring risk_level="high" | timeslice 1h | count by _timeslice',
                    'visualization': 'line_chart'
                },
                {
                    'title': 'Policy Violations Over Time',
                    'query': '_sourceCategory=security_alerts alert_type="ai_usage_violation" | timeslice 1d | count by _timeslice',
                    'visualization': 'area_chart'
                },
                {
                    'title': 'Top AI Tools by Usage',
                    'query': '_sourceCategory=ai_usage_monitoring | json field=ai_tool | count by ai_tool | sort by _count desc | limit 10',
                    'visualization': 'bar_chart'
                },
                {
                    'title': 'Sensitive Data Exposure Incidents',
                    'query': '_sourceCategory=ai_usage_monitoring sensitive_data_detected=true | json field=user_id | count by user_id',
                    'visualization': 'table'
                }
            ]
        }
        
        return dashboard_config

class Rapid7AISecurityIntegration:
    """Integration with Rapid7 InsightIDR for AI usage security monitoring"""
    
    def __init__(self, rapid7_api_key: str, region: str = "us"):
        self.api_key = rapid7_api_key
        self.base_url = f"https://{region}.api.insight.rapid7.com"
        self.headers = {
            'X-Api-Key': rapid7_api_key,
            'Content-Type': 'application/json'
        }
    
    def create_ai_usage_log_source(self) -> Dict:
        """Create log source in Rapid7 for AI usage events"""
        log_source_config = {
            'name': 'AI Usage Monitoring',
            'description': 'Centralized AI tool usage and security monitoring',
            'source_type': 'Custom Application Log',
            'collection_method': 'API',
            'log_format': 'JSON',
            'timezone': 'UTC',
            'enabled': True
        }
        
        url = f"{self.base_url}/idr/v1/customlogs/sources"
        
        try:
            response = requests.post(url, headers=self.headers, json=log_source_config)
            
            if response.status_code == 201:
                return response.json()
            else:
                return {'error': f'Failed to create log source: {response.status_code}'}
        except Exception as e:
            return {'error': f'API call failed: {e}'}
    
    def send_ai_security_event(self, event_data: Dict) -> bool:
        """Send AI security events to Rapid7 InsightIDR"""
        
        # Transform to Rapid7 event format
        rapid7_event = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'source_ip': event_data.get('source_ip', '0.0.0.0'),
            'destination_ip': event_data.get('destination_ip', '0.0.0.0'),
            'user_name': event_data.get('user_id', 'unknown'),
            'event_type': 'AI_USAGE_SECURITY_EVENT',
            'severity': self._map_severity_to_rapid7(event_data.get('severity', 'medium')),
            'description': f"AI Usage Security Event: {event_data.get('description', 'Unknown event')}",
            'custom_fields': {
                'ai_tool': event_data.get('ai_tool'),
                'risk_level': event_data.get('risk_level'),
                'policy_violation': event_data.get('policy_violation'),
                'sensitive_data_detected': event_data.get('sensitive_data_detected', False),
                'compliance_impact': event_data.get('compliance_impact'),
                'remediation_status': event_data.get('remediation_status', 'pending'),
                'department': event_data.get('department'),
                'session_duration': event_data.get('session_duration', 0),
                'data_volume': event_data.get('data_volume', 0)
            }
        }
        
        url = f"{self.base_url}/idr/v1/customlogs/sources/ai-usage-monitoring/logs"
        
        try:
            response = requests.post(url, headers=self.headers, json=rapid7_event)
            return response.status_code in [200, 201, 202]
        except Exception as e:
            print(f"Failed to send event to Rapid7: {e}")
            return False
    
    def create_ai_usage_investigation(self, incident_data: Dict) -> Dict:
        """Create investigation in Rapid7 for AI usage incidents"""
        
        investigation = {
            'title': f"AI Usage Security Incident - {incident_data.get('incident_type', 'Unknown')}",
            'description': f"""
            AI Usage Security Incident Details:
            
            User: {incident_data.get('user_id', 'Unknown')}
            AI Tool: {incident_data.get('ai_tool', 'Unknown')}
            Incident Type: {incident_data.get('incident_type', 'Unknown')}
            Risk Level: {incident_data.get('risk_level', 'Unknown')}
            
            Detection Details:
            - Timestamp: {incident_data.get('timestamp', 'Unknown')}
            - Source IP: {incident_data.get('source_ip', 'Unknown')}
            - Sensitive Data Detected: {incident_data.get('sensitive_data_detected', False)}
            - Policy Violations: {', '.join(incident_data.get('policy_violations', []))}
            
            Recommended Actions:
            {chr(10).join(incident_data.get('recommended_actions', ['Review incident details', 'Assess compliance impact']))}
            """,
            'priority': self._map_priority_to_rapid7(incident_data.get('priority', 'medium')),
            'assignee': incident_data.get('assignee', 'security-team'),
            'tags': ['ai-usage', 'security-incident', incident_data.get('risk_level', 'medium')],
            'custom_fields': {
                'ai_tool': incident_data.get('ai_tool'),
                'affected_user': incident_data.get('user_id'),
                'compliance_frameworks': incident_data.get('compliance_frameworks', []),
                'business_impact': incident_data.get('business_impact', 'low')
            }
        }
        
        url = f"{self.base_url}/idr/v1/investigations"
        
        try:
            response = requests.post(url, headers=self.headers, json=investigation)
            
            if response.status_code == 201:
                return response.json()
            else:
                return {'error': f'Failed to create investigation: {response.status_code}'}
        except Exception as e:
            return {'error': f'Investigation creation failed: {e}'}
    
    def query_ai_usage_threats(self, start_time: str, end_time: str) -> Dict:
        """Query Rapid7 for AI usage-related threats and incidents"""
        
        query = {
            'leql': f"""
            WHERE(source_ip EXISTS AND event_type = 'AI_USAGE_SECURITY_EVENT')
            DURING({start_time} TO {end_time})
            GROUPBY(custom_fields.ai_tool, custom_fields.risk_level)
            CALCULATE(COUNT)
            """,
            'time_range': {
                'from': start_time,
                'to': end_time
            }
        }
        
        url = f"{self.base_url}/idr/v1/query"
        
        try:
            response = requests.post(url, headers=self.headers, json=query)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': f'Query failed: {response.status_code}'}
        except Exception as e:
            return {'error': f'Query execution failed: {e}'}
    
    def _map_severity_to_rapid7(self, severity: str) -> str:
        """Map internal severity to Rapid7 severity levels"""
        mapping = {
            'low': 'Low',
            'medium': 'Medium', 
            'high': 'High',
            'critical': 'Critical'
        }
        return mapping.get(severity.lower(), 'Medium')
    
    def _map_priority_to_rapid7(self, priority: str) -> str:
        """Map internal priority to Rapid7 priority levels"""
        mapping = {
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High', 
            'critical': 'Critical'
        }
        return mapping.get(priority.lower(), 'Medium')

class JiraAIIncidentManagement:
    """Integration with Jira for AI usage incident and compliance management"""
    
    def __init__(self, jira_url: str, username: str, api_token: str, project_key: str):
        self.jira_url = jira_url
        self.auth = (username, api_token)
        self.project_key = project_key
        self.headers = {'Content-Type': 'application/json'}
    
    def create_ai_compliance_ticket(self, compliance_data: Dict) -> Dict:
        """Create Jira ticket for AI compliance violations"""
        
        ticket_data = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': f"AI Compliance Violation - {compliance_data.get('violation_type', 'Unknown')}",
                'description': f"""
                *AI Compliance Violation Detected*
                
                *User Details:*
                - User ID: {compliance_data.get('user_id', 'Unknown')}
                - Department: {compliance_data.get('department', 'Unknown')}
                - Manager: {compliance_data.get('manager', 'TBD')}
                
                *Violation Details:*
                - AI Tool: {compliance_data.get('ai_tool', 'Unknown')}
                - Violation Type: {compliance_data.get('violation_type', 'Unknown')}
                - Risk Level: {compliance_data.get('risk_level', 'Unknown')}
                - Detection Time: {compliance_data.get('detection_time', 'Unknown')}
                
                *Compliance Impact:*
                - Frameworks Affected: {', '.join(compliance_data.get('compliance_frameworks', []))}
                - Sensitive Data Types: {', '.join(compliance_data.get('sensitive_data_types', []))}
                - Business Impact: {compliance_data.get('business_impact', 'To be assessed')}
                
                *Immediate Actions Required:*
                {chr(10).join(f'• {action}' for action in compliance_data.get('immediate_actions', ['Investigate violation', 'Assess impact']))}
                
                *Evidence:*
                - Content Hash: {compliance_data.get('content_hash', 'N/A')}
                - Source IP: {compliance_data.get('source_ip', 'Unknown')}
                - Session Duration: {compliance_data.get('session_duration', 0)} minutes
                """,
                'issuetype': {'name': 'Task'},
                'priority': {'name': self._map_priority_to_jira(compliance_data.get('priority', 'medium'))},
                'assignee': {'name': compliance_data.get('assignee', 'compliance-team')},
                'labels': [
                    'ai-compliance',
                    f"risk-{compliance_data.get('risk_level', 'medium').lower()}",
                    f"tool-{compliance_data.get('ai_tool', 'unknown').lower().replace(' ', '-')}"
                ],
                'customfield_10001': compliance_data.get('user_id'),  # Custom field for User ID
                'customfield_10002': compliance_data.get('ai_tool'),  # Custom field for AI Tool
                'customfield_10003': compliance_data.get('risk_level')  # Custom field for Risk Level
            }
        }
        
        url = f"{self.jira_url}/rest/api/3/issue"
        
        try:
            response = requests.post(url, auth=self.auth, headers=self.headers, json=ticket_data)
            
            if response.status_code == 201:
                return response.json()
            else:
                return {'error': f'Failed to create ticket: {response.status_code}', 'details': response.text}
        except Exception as e:
            return {'error': f'Ticket creation failed: {e}'}
    
    def create_ai_security_incident(self, incident_data: Dict) -> Dict:
        """Create Jira security incident for AI usage violations"""
        
        incident_ticket = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': f"AI Security Incident - {incident_data.get('incident_type', 'Data Exposure')}",
                'description': f"""
                *SECURITY INCIDENT - AI Tool Usage*
                
                *Incident Classification:*
                - Type: {incident_data.get('incident_type', 'Unknown')}
                - Severity: {incident_data.get('severity', 'Medium')}
                - Confidence Level: {incident_data.get('confidence_level', 'Medium')}
                
                *Affected User:*
                - User ID: {incident_data.get('user_id', 'Unknown')}
                - Department: {incident_data.get('department', 'Unknown')}
                - Location: {incident_data.get('location', 'Unknown')}
                
                *Technical Details:*
                - AI Tool: {incident_data.get('ai_tool', 'Unknown')}
                - Source IP: {incident_data.get('source_ip', 'Unknown')}
                - Detection Method: {incident_data.get('detection_method', 'Automated')}
                - Timestamp: {incident_data.get('timestamp', 'Unknown')}
                
                *Security Impact:*
                - Data Classification: {incident_data.get('data_classification', 'Unknown')}
                - Potential Exposure: {incident_data.get('potential_exposure', 'To be determined')}
                - Compliance Implications: {', '.join(incident_data.get('compliance_implications', []))}
                
                *Response Actions:*
                {chr(10).join(f'• {action}' for action in incident_data.get('response_actions', ['Investigate incident', 'Contain exposure']))}
                
                *Investigation Notes:*
                {incident_data.get('investigation_notes', 'Initial detection - investigation required')}
                """,
                'issuetype': {'name': 'Bug'},  # Using Bug for security incidents
                'priority': {'name': self._map_severity_to_jira_priority(incident_data.get('severity', 'medium'))},
                'assignee': {'name': incident_data.get('assignee', 'security-team')},
                'labels': [
                    'security-incident',
                    'ai-usage',
                    f"severity-{incident_data.get('severity', 'medium').lower()}",
                    'data-exposure'
                ],
                'components': [{'name': 'Security'}],
                'customfield_10004': incident_data.get('incident_id'),  # Custom field for Incident ID
                'customfield_10005': incident_data.get('affected_systems', []),  # Custom field for Affected Systems
                'customfield_10006': incident_data.get('containment_status', 'Open')  # Custom field for Containment Status
            }
        }
        
        url = f"{self.jira_url}/rest/api/3/issue"
        
        try:
            response = requests.post(url, auth=self.auth, headers=self.headers, json=incident_ticket)
            
            if response.status_code == 201:
                ticket_response = response.json()
                
                # Add security incident workflow transitions
                self._transition_security_incident(ticket_response['key'], 'In Progress')
                
                return ticket_response
            else:
                return {'error': f'Failed to create security incident: {response.status_code}'}
        except Exception as e:
            return {'error': f'Security incident creation failed: {e}'}
    
    def create_ai_policy_review_task(self, review_data: Dict) -> Dict:
        """Create Jira task for AI policy review and updates"""
        
        task_data = {
            'fields': {
                'project': {'key': self.project_key},
                'summary': f"AI Policy Review - {review_data.get('policy_area', 'General')}",
                'description': f"""
                *AI Policy Review Required*
                
                *Review Trigger:*
                - Trigger Event: {review_data.get('trigger_event', 'Scheduled review')}
                - Priority: {review_data.get('priority', 'Medium')}
                - Due Date: {review_data.get('due_date', 'TBD')}
                
                *Policy Areas for Review:*
                {chr(10).join(f'• {area}' for area in review_data.get('policy_areas', ['General AI usage']))}
                
                *Recent Incidents/Trends:*
                - Compliance Violations: {review_data.get('recent_violations', 0)}
                - New AI Tools Detected: {', '.join(review_data.get('new_tools', []))}
                - Risk Level Changes: {review_data.get('risk_changes', 'None')}
                
                *Stakeholders to Involve:*
                {chr(10).join(f'• {stakeholder}' for stakeholder in review_data.get('stakeholders', ['Legal', 'Security', 'HR']))}
                
                *Review Objectives:*
                {chr(10).join(f'• {objective}' for objective in review_data.get('objectives', ['Update policy language', 'Address new risks']))}
                
                *Success Criteria:*
                {chr(10).join(f'• {criteria}' for criteria in review_data.get('success_criteria', ['Policy updated', 'Training materials revised']))}
                """,
                'issuetype': {'name': 'Task'},
                'priority': {'name': self._map_priority_to_jira(review_data.get('priority', 'medium'))},
                'assignee': {'name': review_data.get('assignee', 'policy-team')},
                'labels': [
                    'ai-policy',
                    'governance',
                    'compliance-review'
                ],
                'duedate': review_data.get('due_date'),
                'customfield_10007': review_data.get('policy_version'),  # Custom field for Policy Version
                'customfield_10008': review_data.get('review_type', 'Scheduled')  # Custom field for Review Type
            }
        }
        
        url = f"{self.jira_url}/rest/api/3/issue"
        
        try:
            response = requests.post(url, auth=self.auth, headers=self.headers, json=task_data)
            
            if response.status_code == 201:
                return response.json()
            else:
                return {'error': f'Failed to create policy review task: {response.status_code}'}
        except Exception as e:
            return {'error': f'Policy review task creation failed: {e}'}
    
    def get_ai_incident_metrics(self, start_date: str, end_date: str) -> Dict:
        """Get AI incident metrics from Jira for reporting"""
        
        jql_query = f"""
        project = {self.project_key} 
        AND labels in (ai-compliance, security-incident, ai-usage) 
        AND created >= '{start_date}' 
        AND created <= '{end_date}'
        """
        
        url = f"{self.jira_url}/rest/api/3/search"
        params = {
            'jql': jql_query,
            'fields': 'summary,status,priority,created,resolved,assignee,labels,customfield_10003',
            'maxResults': 1000
        }
        
        try:
            response = requests.get(url, auth=self.auth, params=params)
            
            if response.status_code == 200:
                issues = response.json()['issues']
                
                # Analyze metrics
                metrics = {
                    'total_incidents': len(issues),
                    'by_priority': {},
                    'by_status': {},
                    'by_risk_level': {},
                    'resolution_times': [],
                    'open_incidents': 0
                }
                
                for issue in issues:
                    # Priority distribution
                    priority = issue['fields']['priority']['name']
                    metrics['by_priority'][priority] = metrics['by_priority'].get(priority, 0) + 1
                    
                    # Status distribution
                    status = issue['fields']['status']['name']
                    metrics['by_status'][status] = metrics['by_status'].get(status, 0) + 1
                    
                    if status not in ['Done', 'Resolved', 'Closed']:
                        metrics['open_incidents'] += 1
                    
                    # Risk level distribution (from custom field)
                    risk_level = issue['fields'].get('customfield_10003', 'Unknown')
                    metrics['by_risk_level'][risk_level] = metrics['by_risk_level'].get(risk_level, 0) + 1
                    
                    # Resolution time calculation
                    if issue['fields']['resolved']:
                        created = datetime.fromisoformat(issue['fields']['created'].replace('Z', '+00:00'))
                        resolved = datetime.fromisoformat(issue['fields']['resolved'].replace('Z', '+00:00'))
                        resolution_time = (resolved - created).total_seconds() / 3600  # Hours
                        metrics['resolution_times'].append(resolution_time)
                
                # Calculate average resolution time
                if metrics['resolution_times']:
                    metrics['avg_resolution_time_hours'] = sum(metrics['resolution_times']) / len(metrics['resolution_times'])
                else:
                    metrics['avg_resolution_time_hours'] = 0
                
                return metrics
            else:
                return {'error': f'Failed to fetch incidents: {response.status_code}'}
        except Exception as e:
            return {'error': f'Metrics retrieval failed: {e}'}
    
    def _transition_security_incident(self, issue_key: str, transition_name: str) -> bool:
        """Transition security incident through workflow"""
        
        # Get available transitions
        transitions_url = f"{self.jira_url}/rest/api/3/issue/{issue_key}/transitions"
        
        try:
            response = requests.get(transitions_url, auth=self.auth)
            
            if response.status_code == 200:
                transitions = response.json()['transitions']
                
                # Find the transition ID
                transition_id = None
                for transition in transitions:
                    if transition['name'] == transition_name:
                        transition_id = transition['id']
                        break
                
                if transition_id:
                    # Execute transition
                    transition_data = {
                        'transition': {'id': transition_id}
                    }
                    
                    transition_response = requests.post(
                        transitions_url,
                        auth=self.auth,
                        headers=self.headers,
                        json=transition_data
                    )
                    
                    return transition_response.status_code == 204
            
            return False
        except Exception as e:
            print(f"Failed to transition issue {issue_key}: {e}")
            return False
    
    def _map_priority_to_jira(self, priority: str) -> str:
        """Map internal priority to Jira priority"""
        mapping = {
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'critical': 'Highest'
        }
        return mapping.get(priority.lower(), 'Medium')
    
    def _map_severity_to_jira_priority(self, severity: str) -> str:
        """Map security severity to Jira priority"""
        mapping = {
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'critical': 'Highest'
        }
        return mapping.get(severity.lower(), 'Medium')

# Integrated Workflow Orchestrator
class AIMonitoringWorkflowOrchestrator:
    """Orchestrates AI monitoring workflows across Sumo Logic, Rapid7, and Jira"""
    
    def __init__(self, sumo_config: Dict, rapid7_config: Dict, jira_config: Dict):
        self.sumo = SumoLogicAIMonitoringIntegration(**sumo_config)
        self.rapid7 = Rapid7AISecurityIntegration(**rapid7_config)
        self.jira = JiraAIIncidentManagement(**jira_config)
    
    def process_ai_security_incident(self, incident_data: Dict) -> Dict:
        """Process complete AI security incident workflow"""
        
        results = {
            'incident_id': incident_data.get('incident_id', f"AI-{datetime.now().strftime('%Y%m%d-%H%M%S')}"),
            'sumo_logged': False,
            'rapid7_investigation': None,
            'jira_ticket': None,
            'workflow_status': 'failed'
        }
        
        try:
            # 1. Log to Sumo Logic for analytics and alerting
            sumo_success = self.sumo.send_security_alert({
                'severity': incident_data.get('severity', 'medium'),
                'user_id': incident_data.get('user_id'),
                'violation_type': incident_data.get('violation_type'),
                'ai_tool': incident_data.get('ai_tool'),
                'sensitive_data_types': incident_data.get('sensitive_data_types', []),
                'risk_score': incident_data.get('risk_score', 5),
                'source_ip': incident_data.get('source_ip'),
                'detection_method': 'automated_monitoring',
                'content_hash': incident_data.get('content_hash')
            })
            results['sumo_logged'] = sumo_success
            
            # 2. Create investigation in Rapid7 for security analysis
            if incident_data.get('severity') in ['high', 'critical']:
                rapid7_investigation = self.rapid7.create_ai_usage_investigation({
                    'incident_type': incident_data.get('violation_type'),
                    'user_id': incident_data.get('user_id'),
                    'ai_tool': incident_data.get('ai_tool'),
                    'risk_level': incident_data.get('severity'),
                    'timestamp': incident_data.get('timestamp', datetime.utcnow().isoformat()),
                    'source_ip': incident_data.get('source_ip'),
                    'sensitive_data_detected': incident_data.get('sensitive_data_detected', False),
                    'policy_violations': incident_data.get('policy_violations', []),
                    'priority': incident_data.get('severity'),
                    'assignee': 'security-team',
                    'recommended_actions': [
                        'Analyze user behavior patterns',
                        'Review AI tool access logs',
                        'Assess data exposure risk',
                        'Coordinate with compliance team'
                    ]
                })
                results['rapid7_investigation'] = rapid7_investigation
            
            # 3. Create Jira ticket for incident management
            jira_ticket = self.jira.create_ai_security_incident({
                'incident_type': incident_data.get('violation_type', 'Data Exposure'),
                'severity': incident_data.get('severity', 'medium'),
                'user_id': incident_data.get('user_id'),
                'department': incident_data.get('department'),
                'ai_tool': incident_data.get('ai_tool'),
                'source_ip': incident_data.get('source_ip'),
                'detection_method': 'Automated AI Monitoring',
                'timestamp': incident_data.get('timestamp', datetime.utcnow().isoformat()),
                'data_classification': incident_data.get('data_classification', 'Internal'),
                'compliance_implications': incident_data.get('compliance_frameworks', []),
                'incident_id': results['incident_id'],
                'assignee': 'security-team'
            })
            results['jira_ticket'] = jira_ticket
            
            # 4. Determine overall workflow status
            if sumo_success and jira_ticket and 'error' not in jira_ticket:
                results['workflow_status'] = 'success'
            elif sumo_success or (jira_ticket and 'error' not in jira_ticket):
                results['workflow_status'] = 'partial_success'
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results
    
    def process_compliance_violation(self, violation_data: Dict) -> Dict:
        """Process AI compliance violation workflow"""
        
        results = {
            'violation_id': violation_data.get('violation_id', f"COMP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"),
            'sumo_logged': False,
            'jira_ticket': None,
            'workflow_status': 'failed'
        }
        
        try:
            # 1. Log compliance violation to Sumo Logic
            sumo_success = self.sumo.send_ai_usage_logs({
                'user_id': violation_data.get('user_id'),
                'department': violation_data.get('department'),
                'tool_name': violation_data.get('ai_tool'),
                'risk_level': 'high',
                'compliance_status': 'violation',
                'sensitive_data_detected': violation_data.get('sensitive_data_detected', False),
                'policy_violations': violation_data.get('policy_violations', []),
                'source_ip': violation_data.get('source_ip')
            })
            results['sumo_logged'] = sumo_success
            
            # 2. Create Jira compliance ticket
            jira_ticket = self.jira.create_ai_compliance_ticket({
                'violation_type': violation_data.get('violation_type'),
                'user_id': violation_data.get('user_id'),
                'department': violation_data.get('department'),
                'ai_tool': violation_data.get('ai_tool'),
                'risk_level': violation_data.get('risk_level', 'high'),
                'detection_time': violation_data.get('detection_time', datetime.utcnow().isoformat()),
                'compliance_frameworks': violation_data.get('compliance_frameworks', []),
                'sensitive_data_types': violation_data.get('sensitive_data_types', []),
                'business_impact': violation_data.get('business_impact', 'Medium'),
                'immediate_actions': violation_data.get('immediate_actions', []),
                'content_hash': violation_data.get('content_hash'),
                'source_ip': violation_data.get('source_ip'),
                'priority': violation_data.get('priority', 'high'),
                'assignee': 'compliance-team'
            })
            results['jira_ticket'] = jira_ticket
            
            # 3. Determine workflow status
            if sumo_success and jira_ticket and 'error' not in jira_ticket:
                results['workflow_status'] = 'success'
            elif sumo_success or (jira_ticket and 'error' not in jira_ticket):
                results['workflow_status'] = 'partial_success'
            
            return results
            
        except Exception as e:
            results['error'] = str(e)
            return results

# Usage Examples
if __name__ == "__main__":
    # Configuration
    sumo_config = {
        'sumo_endpoint': 'https://collectors.sumologic.com/receiver/v1/http/your-endpoint',
        'access_id': 'your-access-id',
        'access_key': 'your-access-key'
    }
    
    rapid7_config = {
        'rapid7_api_key': 'your-rapid7-api-key',
        'region': 'us'
    }
    
    jira_config = {
        'jira_url': 'https://your-company.atlassian.net',
        'username': 'your-email@company.com',
        'api_token': 'your-jira-api-token',
        'project_key': 'AISEC'
    }
    
    # Initialize orchestrator
    orchestrator = AIMonitoringWorkflowOrchestrator(sumo_config, rapid7_config, jira_config)
    
    # Example: Process security incident
    incident_data = {
        'severity': 'high',
        'user_id': 'john.doe@company.com',
        'violation_type': 'sensitive_data_exposure',
        'ai_tool': 'ChatGPT',
        'sensitive_data_types': ['email', 'phone'],
        'risk_score': 8,
        'source_ip': '192.168.1.100',
        'department': 'Marketing',
        'sensitive_data_detected': True,
        'policy_violations': ['external_ai_usage', 'pii_exposure']
    }
    
    result = orchestrator.process_ai_security_incident(incident_data)
    print("Security Incident Processing Result:", json.dumps(result, indent=2))