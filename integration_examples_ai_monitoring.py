"""
Real-World Integration Examples for AI Usage Monitoring
Practical implementations for common enterprise scenarios
"""

import json
import requests
import pandas as pd
from datetime import datetime, timedelta
import sqlite3
import hashlib
import re
from typing import Dict, List, Any

class GitHubCopilotMonitor:
    """Monitor GitHub Copilot usage through GitHub API and telemetry"""
    
    def __init__(self, github_token: str, org_name: str):
        self.github_token = github_token
        self.org_name = org_name
        self.headers = {
            'Authorization': f'token {github_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
    
    def get_copilot_usage_metrics(self) -> Dict:
        """Get Copilot usage metrics from GitHub API"""
        url = f'https://api.github.com/orgs/{self.org_name}/copilot/usage'
        
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            usage_data = response.json()
            
            # Process usage data
            processed_data = []
            for day_data in usage_data:
                processed_data.append({
                    'date': day_data['day'],
                    'total_suggestions': day_data['total_suggestions_count'],
                    'total_acceptances': day_data['total_acceptances_count'],
                    'total_lines_suggested': day_data['total_lines_suggested'],
                    'total_lines_accepted': day_data['total_lines_accepted'],
                    'total_active_users': day_data['total_active_users'],
                    'acceptance_rate': (day_data['total_acceptances_count'] / 
                                      day_data['total_suggestions_count'] 
                                      if day_data['total_suggestions_count'] > 0 else 0)
                })
            
            return {
                'organization': self.org_name,
                'usage_data': processed_data,
                'summary': self._calculate_summary(processed_data)
            }
        else:
            raise Exception(f"Failed to fetch Copilot usage: {response.status_code}")
    
    def get_copilot_seat_assignments(self) -> List[Dict]:
        """Get list of users with Copilot seats"""
        url = f'https://api.github.com/orgs/{self.org_name}/copilot/billing/seats'
        
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            seats_data = response.json()
            
            users = []
            for seat in seats_data['seats']:
                users.append({
                    'username': seat['assignee']['login'],
                    'user_id': seat['assignee']['id'],
                    'created_at': seat['created_at'],
                    'updated_at': seat['updated_at'],
                    'pending_cancellation_date': seat.get('pending_cancellation_date'),
                    'last_activity_at': seat.get('last_activity_at')
                })
            
            return users
        else:
            raise Exception(f"Failed to fetch Copilot seats: {response.status_code}")
    
    def _calculate_summary(self, usage_data: List[Dict]) -> Dict:
        """Calculate summary statistics"""
        if not usage_data:
            return {}
        
        df = pd.DataFrame(usage_data)
        
        return {
            'total_suggestions': df['total_suggestions'].sum(),
            'total_acceptances': df['total_acceptances'].sum(),
            'avg_acceptance_rate': df['acceptance_rate'].mean(),
            'peak_active_users': df['total_active_users'].max(),
            'avg_active_users': df['total_active_users'].mean(),
            'total_lines_generated': df['total_lines_suggested'].sum(),
            'total_lines_accepted': df['total_lines_accepted'].sum()
        }

class Office365CopilotMonitor:
    """Monitor Microsoft 365 Copilot usage through Microsoft Graph API"""
    
    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = self._get_access_token()
    
    def _get_access_token(self) -> str:
        """Get access token for Microsoft Graph API"""
        url = f'https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token'
        
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        
        response = requests.post(url, data=data)
        
        if response.status_code == 200:
            return response.json()['access_token']
        else:
            raise Exception(f"Failed to get access token: {response.status_code}")
    
    def get_copilot_usage_reports(self, period_days: int = 30) -> Dict:
        """Get Copilot usage reports from Microsoft Graph"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        # Get user activity reports
        end_date = datetime.now()
        start_date = end_date - timedelta(days=period_days)
        
        url = f'https://graph.microsoft.com/v1.0/reports/getM365AppUserDetail(period=\'D{period_days}\')'
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            # Parse CSV response
            csv_data = response.text
            lines = csv_data.strip().split('\n')
            
            if len(lines) > 1:
                headers_line = lines[0].split(',')
                data_lines = [line.split(',') for line in lines[1:]]
                
                usage_data = []
                for data_line in data_lines:
                    if len(data_line) >= len(headers_line):
                        user_data = dict(zip(headers_line, data_line))
                        
                        # Filter for Copilot usage
                        if any('copilot' in key.lower() for key in user_data.keys()):
                            usage_data.append(user_data)
                
                return {
                    'period_days': period_days,
                    'users_with_copilot_activity': len(usage_data),
                    'usage_details': usage_data
                }
        
        return {'error': 'Failed to fetch usage reports'}
    
    def get_audit_logs_for_copilot(self, start_date: str, end_date: str) -> List[Dict]:
        """Get audit logs for Copilot activities"""
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        # Search audit logs for Copilot activities
        url = 'https://graph.microsoft.com/v1.0/security/auditLog/queries'
        
        query_data = {
            'displayName': 'Copilot Usage Audit',
            'filterStartDateTime': start_date,
            'filterEndDateTime': end_date,
            'recordTypeFilters': ['CopilotInteraction']
        }
        
        response = requests.post(url, headers=headers, json=query_data)
        
        if response.status_code == 201:
            query_id = response.json()['id']
            
            # Poll for results
            results_url = f'https://graph.microsoft.com/v1.0/security/auditLog/queries/{query_id}'
            
            # Wait for query completion (simplified)
            import time
            time.sleep(10)
            
            results_response = requests.get(results_url, headers=headers)
            
            if results_response.status_code == 200:
                return results_response.json().get('records', [])
        
        return []

class SlackAIUsageMonitor:
    """Monitor AI usage in Slack (AI apps, bots, integrations)"""
    
    def __init__(self, slack_token: str):
        self.slack_token = slack_token
        self.headers = {
            'Authorization': f'Bearer {slack_token}',
            'Content-Type': 'application/json'
        }
    
    def get_ai_app_usage(self) -> Dict:
        """Get usage statistics for AI apps in Slack"""
        # Get list of installed apps
        apps_url = 'https://slack.com/api/apps.list'
        
        response = requests.get(apps_url, headers=self.headers)
        
        if response.status_code == 200:
            apps_data = response.json()
            
            ai_apps = []
            ai_keywords = ['ai', 'bot', 'assistant', 'gpt', 'claude', 'copilot']
            
            for app in apps_data.get('apps', []):
                app_name = app.get('name', '').lower()
                app_description = app.get('description', '').lower()
                
                if any(keyword in app_name or keyword in app_description 
                       for keyword in ai_keywords):
                    ai_apps.append({
                        'app_id': app['id'],
                        'app_name': app['name'],
                        'description': app.get('description', ''),
                        'is_distributed': app.get('is_distributed', False),
                        'is_workflow_app': app.get('is_workflow_app', False)
                    })
            
            return {
                'total_ai_apps': len(ai_apps),
                'ai_apps': ai_apps
            }
        
        return {'error': 'Failed to fetch apps'}
    
    def analyze_ai_conversations(self, channel_id: str, days: int = 7) -> Dict:
        """Analyze conversations for AI-generated content"""
        # Get conversation history
        history_url = 'https://slack.com/api/conversations.history'
        
        oldest = (datetime.now() - timedelta(days=days)).timestamp()
        
        params = {
            'channel': channel_id,
            'oldest': oldest,
            'limit': 1000
        }
        
        response = requests.get(history_url, headers=self.headers, params=params)
        
        if response.status_code == 200:
            messages_data = response.json()
            
            ai_indicators = [
                'generated by ai', 'ai-generated', 'chatgpt', 'claude',
                'copilot', 'artificial intelligence', 'machine learning'
            ]
            
            ai_messages = []
            total_messages = len(messages_data.get('messages', []))
            
            for message in messages_data.get('messages', []):
                text = message.get('text', '').lower()
                
                if any(indicator in text for indicator in ai_indicators):
                    ai_messages.append({
                        'user': message.get('user'),
                        'timestamp': message.get('ts'),
                        'text': message.get('text'),
                        'ai_confidence': self._calculate_ai_confidence(text)
                    })
            
            return {
                'channel_id': channel_id,
                'period_days': days,
                'total_messages': total_messages,
                'ai_messages_detected': len(ai_messages),
                'ai_usage_percentage': (len(ai_messages) / total_messages * 100) if total_messages > 0 else 0,
                'ai_messages': ai_messages
            }
        
        return {'error': 'Failed to fetch conversation history'}
    
    def _calculate_ai_confidence(self, text: str) -> float:
        """Calculate confidence that text is AI-generated"""
        ai_patterns = [
            r'as an ai', r'i\'m an ai', r'artificial intelligence',
            r'machine learning', r'generated by', r'created with ai'
        ]
        
        confidence = 0.0
        for pattern in ai_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                confidence += 0.2
        
        return min(confidence, 1.0)

class NetworkTrafficAIMonitor:
    """Monitor network traffic for AI service usage"""
    
    def __init__(self):
        self.ai_domains = {
            'openai.com': 'OpenAI/ChatGPT',
            'api.openai.com': 'OpenAI API',
            'claude.ai': 'Anthropic Claude',
            'api.anthropic.com': 'Anthropic API',
            'bard.google.com': 'Google Bard',
            'copilot.microsoft.com': 'Microsoft Copilot',
            'github.com/copilot': 'GitHub Copilot',
            'api.cohere.ai': 'Cohere API',
            'replicate.com': 'Replicate AI'
        }
    
    def analyze_firewall_logs(self, log_file: str) -> Dict:
        """Analyze firewall logs for AI service connections"""
        ai_connections = []
        
        with open(log_file, 'r') as f:
            for line in f:
                # Parse firewall log format (example format)
                # timestamp,source_ip,dest_ip,dest_port,protocol,action,bytes
                parts = line.strip().split(',')
                
                if len(parts) >= 7:
                    timestamp, source_ip, dest_ip, dest_port, protocol, action, bytes_transferred = parts
                    
                    # Resolve destination IP to domain (simplified)
                    domain = self._resolve_ip_to_domain(dest_ip)
                    
                    if domain and any(ai_domain in domain for ai_domain in self.ai_domains.keys()):
                        ai_service = next((service for ai_domain, service in self.ai_domains.items() 
                                         if ai_domain in domain), 'Unknown AI Service')
                        
                        ai_connections.append({
                            'timestamp': timestamp,
                            'source_ip': source_ip,
                            'destination_domain': domain,
                            'ai_service': ai_service,
                            'bytes_transferred': int(bytes_transferred),
                            'action': action
                        })
        
        # Analyze patterns
        analysis = self._analyze_connection_patterns(ai_connections)
        
        return {
            'total_ai_connections': len(ai_connections),
            'connections': ai_connections,
            'analysis': analysis
        }
    
    def monitor_dns_queries(self, dns_log_file: str) -> Dict:
        """Monitor DNS queries for AI service domains"""
        ai_queries = []
        
        with open(dns_log_file, 'r') as f:
            for line in f:
                # Parse DNS log format
                if any(domain in line for domain in self.ai_domains.keys()):
                    # Extract query details (format varies by DNS server)
                    query_data = self._parse_dns_query(line)
                    if query_data:
                        ai_queries.append(query_data)
        
        # Group by client and service
        client_usage = {}
        for query in ai_queries:
            client = query['client_ip']
            service = query['ai_service']
            
            if client not in client_usage:
                client_usage[client] = {}
            
            if service not in client_usage[client]:
                client_usage[client][service] = 0
            
            client_usage[client][service] += 1
        
        return {
            'total_ai_queries': len(ai_queries),
            'unique_clients': len(client_usage),
            'client_usage': client_usage,
            'queries': ai_queries
        }
    
    def _resolve_ip_to_domain(self, ip: str) -> str:
        """Resolve IP address to domain name"""
        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def _parse_dns_query(self, log_line: str) -> Dict:
        """Parse DNS query from log line"""
        # Simplified DNS log parsing
        # Format varies by DNS server (BIND, Unbound, etc.)
        
        for domain, service in self.ai_domains.items():
            if domain in log_line:
                # Extract timestamp and client IP (simplified)
                parts = log_line.split()
                if len(parts) >= 3:
                    return {
                        'timestamp': parts[0],
                        'client_ip': parts[1] if '.' in parts[1] else 'unknown',
                        'queried_domain': domain,
                        'ai_service': service
                    }
        
        return None
    
    def _analyze_connection_patterns(self, connections: List[Dict]) -> Dict:
        """Analyze connection patterns for insights"""
        if not connections:
            return {}
        
        df = pd.DataFrame(connections)
        
        # Group by source IP
        by_source = df.groupby('source_ip').agg({
            'bytes_transferred': 'sum',
            'ai_service': 'nunique',
            'timestamp': 'count'
        }).rename(columns={'timestamp': 'connection_count'})
        
        # Identify heavy users
        heavy_users = by_source[by_source['bytes_transferred'] > 1000000].index.tolist()
        
        # Group by AI service
        by_service = df.groupby('ai_service').agg({
            'bytes_transferred': 'sum',
            'source_ip': 'nunique',
            'timestamp': 'count'
        }).rename(columns={'timestamp': 'connection_count', 'source_ip': 'unique_users'})
        
        return {
            'heavy_users': heavy_users,
            'usage_by_source': by_source.to_dict('index'),
            'usage_by_service': by_service.to_dict('index'),
            'total_bandwidth': df['bytes_transferred'].sum(),
            'peak_usage_hour': self._find_peak_usage_hour(df)
        }
    
    def _find_peak_usage_hour(self, df: pd.DataFrame) -> str:
        """Find peak usage hour"""
        try:
            df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
            hourly_usage = df.groupby('hour')['bytes_transferred'].sum()
            peak_hour = hourly_usage.idxmax()
            return f"{peak_hour:02d}:00"
        except:
            return "unknown"

class ComplianceAuditor:
    """Generate compliance reports and audit trails"""
    
    def __init__(self, db_path: str = "ai_usage.db"):
        self.db_path = db_path
    
    def generate_sox_compliance_report(self, start_date: str, end_date: str) -> Dict:
        """Generate SOX compliance report for AI usage"""
        conn = sqlite3.connect(self.db_path)
        
        # Get financial system AI usage
        financial_usage = pd.read_sql_query('''
            SELECT user_id, tool_name, session_duration, timestamp
            FROM business_ai_usage 
            WHERE department IN ('Finance', 'Accounting', 'Treasury')
            AND timestamp BETWEEN ? AND ?
        ''', conn, params=(start_date, end_date))
        
        # Get high-risk content analysis
        high_risk_content = pd.read_sql_query('''
            SELECT user_id, content_type, compliance_risk_level, timestamp
            FROM content_analysis 
            WHERE compliance_risk_level = 'HIGH'
            AND timestamp BETWEEN ? AND ?
        ''', conn, params=(start_date, end_date))
        
        conn.close()
        
        return {
            'report_type': 'SOX Compliance',
            'period': f"{start_date} to {end_date}",
            'financial_users_with_ai': financial_usage['user_id'].nunique(),
            'total_financial_ai_sessions': len(financial_usage),
            'high_risk_incidents': len(high_risk_content),
            'compliance_status': 'COMPLIANT' if len(high_risk_content) == 0 else 'VIOLATIONS_DETECTED',
            'recommendations': [
                'Review AI usage policies for financial personnel',
                'Implement additional controls for financial data processing',
                'Conduct quarterly AI usage audits'
            ]
        }
    
    def generate_gdpr_data_processing_report(self, start_date: str, end_date: str) -> Dict:
        """Generate GDPR compliance report for AI data processing"""
        conn = sqlite3.connect(self.db_path)
        
        # Get content with sensitive data
        sensitive_data = pd.read_sql_query('''
            SELECT user_id, content_type, sensitive_data_detected, timestamp
            FROM content_analysis 
            WHERE sensitive_data_detected = TRUE
            AND timestamp BETWEEN ? AND ?
        ''', conn, params=(start_date, end_date))
        
        conn.close()
        
        # Analyze data processing activities
        data_subjects_affected = sensitive_data['user_id'].nunique()
        processing_activities = len(sensitive_data)
        
        return {
            'report_type': 'GDPR Data Processing',
            'period': f"{start_date} to {end_date}",
            'data_subjects_affected': data_subjects_affected,
            'processing_activities': processing_activities,
            'lawful_basis': 'Legitimate Interest (Employee Monitoring)',
            'data_retention_period': '7 years',
            'rights_exercised': 0,  # Would track actual rights requests
            'compliance_measures': [
                'Data minimization applied',
                'Purpose limitation enforced',
                'Storage limitation implemented',
                'Security measures in place'
            ]
        }

# Usage Examples and Integration Patterns
if __name__ == "__main__":
    # Example: Monitor GitHub Copilot usage
    github_monitor = GitHubCopilotMonitor('github_token', 'your_org')
    copilot_usage = github_monitor.get_copilot_usage_metrics()
    print("GitHub Copilot Usage:", json.dumps(copilot_usage, indent=2))
    
    # Example: Monitor Office 365 Copilot
    office_monitor = Office365CopilotMonitor('tenant_id', 'client_id', 'client_secret')
    office_usage = office_monitor.get_copilot_usage_reports(30)
    print("Office 365 Copilot Usage:", json.dumps(office_usage, indent=2))
    
    # Example: Analyze network traffic
    network_monitor = NetworkTrafficAIMonitor()
    # network_analysis = network_monitor.analyze_firewall_logs('firewall.log')
    
    # Example: Generate compliance report
    auditor = ComplianceAuditor()
    sox_report = auditor.generate_sox_compliance_report('2024-01-01', '2024-01-31')
    print("SOX Compliance Report:", json.dumps(sox_report, indent=2))