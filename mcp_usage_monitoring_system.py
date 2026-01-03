"""
Model Context Protocol (MCP) Usage Monitoring System
Comprehensive monitoring for MCP servers, clients, and tool usage
"""

import json
import asyncio
import websockets
import sqlite3
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
import logging
from pathlib import Path
import psutil
import threading
import queue

@dataclass
class MCPUsageEvent:
    """Data class for MCP usage events"""
    timestamp: str
    session_id: str
    user_id: str
    client_name: str
    server_name: str
    method: str
    tool_name: Optional[str]
    request_size: int
    response_size: int
    execution_time_ms: float
    success: bool
    error_message: Optional[str]
    sensitive_data_detected: bool
    risk_level: str
    compliance_tags: List[str]
    source_ip: str
    user_agent: str

class MCPProtocolMonitor:
    """Core MCP protocol monitoring with message interception"""
    
    def __init__(self, db_path: str = "mcp_usage.db"):
        self.db_path = db_path
        self.event_queue = queue.Queue()
        self.active_sessions = {}
        self.monitoring_active = False
        self._init_database()
        self._start_event_processor()
    
    def _init_database(self):
        """Initialize SQLite database for MCP usage tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # MCP usage events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mcp_usage_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                session_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                client_name TEXT NOT NULL,
                server_name TEXT NOT NULL,
                method TEXT NOT NULL,
                tool_name TEXT,
                request_size INTEGER DEFAULT 0,
                response_size INTEGER DEFAULT 0,
                execution_time_ms REAL DEFAULT 0,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT,
                sensitive_data_detected BOOLEAN DEFAULT FALSE,
                risk_level TEXT DEFAULT 'low',
                compliance_tags TEXT,
                source_ip TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # MCP server registry table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mcp_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_name TEXT UNIQUE NOT NULL,
                server_type TEXT NOT NULL,
                endpoint TEXT,
                capabilities TEXT,
                security_level TEXT DEFAULT 'medium',
                approved BOOLEAN DEFAULT FALSE,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # MCP client registry table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mcp_clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_name TEXT UNIQUE NOT NULL,
                client_version TEXT,
                user_id TEXT NOT NULL,
                department TEXT,
                approved BOOLEAN DEFAULT FALSE,
                last_activity TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # MCP tool usage table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mcp_tool_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                server_name TEXT NOT NULL,
                user_id TEXT NOT NULL,
                invocation_count INTEGER DEFAULT 1,
                total_execution_time_ms REAL DEFAULT 0,
                success_rate REAL DEFAULT 1.0,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_score REAL DEFAULT 0.0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _start_event_processor(self):
        """Start background thread to process MCP events"""
        def process_events():
            while True:
                try:
                    event = self.event_queue.get(timeout=1)
                    if event is None:  # Shutdown signal
                        break
                    self._store_event(event)
                    self._analyze_event(event)
                except queue.Empty:
                    continue
                except Exception as e:
                    logging.error(f"Error processing MCP event: {e}")
        
        self.processor_thread = threading.Thread(target=process_events, daemon=True)
        self.processor_thread.start()
    
    def intercept_mcp_message(self, message: Dict, direction: str, session_context: Dict) -> Dict:
        """Intercept and analyze MCP protocol messages"""
        
        try:
            # Extract message details
            method = message.get('method', 'unknown')
            message_id = message.get('id', 'unknown')
            params = message.get('params', {})
            
            # Create usage event
            event = MCPUsageEvent(
                timestamp=datetime.utcnow().isoformat(),
                session_id=session_context.get('session_id', 'unknown'),
                user_id=session_context.get('user_id', 'unknown'),
                client_name=session_context.get('client_name', 'unknown'),
                server_name=session_context.get('server_name', 'unknown'),
                method=method,
                tool_name=self._extract_tool_name(method, params),
                request_size=len(json.dumps(message)),
                response_size=0,  # Will be updated on response
                execution_time_ms=0,  # Will be calculated
                success=True,  # Will be updated based on response
                error_message=None,
                sensitive_data_detected=self._detect_sensitive_data(message),
                risk_level=self._assess_risk_level(method, params),
                compliance_tags=self._get_compliance_tags(method, params),
                source_ip=session_context.get('source_ip', 'unknown'),
                user_agent=session_context.get('user_agent', 'unknown')
            )
            
            # Store request timing
            if direction == 'request':
                self.active_sessions[message_id] = {
                    'event': event,
                    'start_time': time.time()
                }
            elif direction == 'response' and message_id in self.active_sessions:
                # Update event with response data
                session_data = self.active_sessions[message_id]
                event = session_data['event']
                event.response_size = len(json.dumps(message))
                event.execution_time_ms = (time.time() - session_data['start_time']) * 1000
                
                # Check for errors
                if 'error' in message:
                    event.success = False
                    event.error_message = str(message['error'])
                
                # Queue event for processing
                self.event_queue.put(event)
                
                # Clean up session tracking
                del self.active_sessions[message_id]
            
            return message  # Return unmodified message
            
        except Exception as e:
            logging.error(f"Error intercepting MCP message: {e}")
            return message
    
    def _extract_tool_name(self, method: str, params: Dict) -> Optional[str]:
        """Extract tool name from MCP method and parameters"""
        if method == 'tools/call':
            return params.get('name')
        elif method == 'tools/list':
            return 'list_tools'
        elif method == 'resources/read':
            return f"read_{params.get('uri', 'unknown')}"
        elif method == 'prompts/get':
            return f"prompt_{params.get('name', 'unknown')}"
        return None
    
    def _detect_sensitive_data(self, message: Dict) -> bool:
        """Detect sensitive data in MCP messages"""
        message_str = json.dumps(message).lower()
        
        sensitive_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            r'\bpassword\b', r'\bapi[_-]?key\b', r'\btoken\b'  # Credentials
        ]
        
        import re
        for pattern in sensitive_patterns:
            if re.search(pattern, message_str, re.IGNORECASE):
                return True
        
        return False
    
    def _assess_risk_level(self, method: str, params: Dict) -> str:
        """Assess risk level of MCP operation"""
        high_risk_methods = ['tools/call', 'resources/write', 'prompts/execute']
        medium_risk_methods = ['resources/read', 'resources/list']
        
        if method in high_risk_methods:
            return 'high'
        elif method in medium_risk_methods:
            return 'medium'
        else:
            return 'low'
    
    def _get_compliance_tags(self, method: str, params: Dict) -> List[str]:
        """Get compliance tags for MCP operation"""
        tags = []
        
        # Data access compliance
        if method in ['resources/read', 'resources/write']:
            tags.append('data_access')
        
        # Tool execution compliance
        if method == 'tools/call':
            tags.append('tool_execution')
            
            # Check for specific compliance requirements
            tool_name = params.get('name', '').lower()
            if 'database' in tool_name or 'sql' in tool_name:
                tags.append('database_access')
            if 'file' in tool_name or 'filesystem' in tool_name:
                tags.append('file_access')
            if 'network' in tool_name or 'http' in tool_name:
                tags.append('network_access')
        
        return tags
    
    def _store_event(self, event: MCPUsageEvent):
        """Store MCP usage event in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO mcp_usage_events 
            (timestamp, session_id, user_id, client_name, server_name, method, 
             tool_name, request_size, response_size, execution_time_ms, success, 
             error_message, sensitive_data_detected, risk_level, compliance_tags, 
             source_ip, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.timestamp, event.session_id, event.user_id, event.client_name,
            event.server_name, event.method, event.tool_name, event.request_size,
            event.response_size, event.execution_time_ms, event.success,
            event.error_message, event.sensitive_data_detected, event.risk_level,
            json.dumps(event.compliance_tags), event.source_ip, event.user_agent
        ))
        
        conn.commit()
        conn.close()
    
    def _analyze_event(self, event: MCPUsageEvent):
        """Analyze MCP event for security and compliance issues"""
        
        # Check for policy violations
        violations = []
        
        # Unauthorized server usage
        if not self._is_server_approved(event.server_name):
            violations.append('unauthorized_server')
        
        # Sensitive data exposure
        if event.sensitive_data_detected:
            violations.append('sensitive_data_exposure')
        
        # High-risk tool usage
        if event.risk_level == 'high' and not self._is_user_authorized(event.user_id, event.tool_name):
            violations.append('unauthorized_tool_usage')
        
        # Excessive usage patterns
        if self._check_excessive_usage(event.user_id, event.server_name):
            violations.append('excessive_usage')
        
        # Generate alerts for violations
        if violations:
            self._generate_security_alert(event, violations)
    
    def _is_server_approved(self, server_name: str) -> bool:
        """Check if MCP server is approved for use"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT approved FROM mcp_servers WHERE server_name = ?', (server_name,))
        result = cursor.fetchone()
        
        conn.close()
        return result and result[0]
    
    def _is_user_authorized(self, user_id: str, tool_name: str) -> bool:
        """Check if user is authorized to use specific tool"""
        # Implement authorization logic based on your policies
        # This is a simplified example
        
        high_privilege_tools = ['database_query', 'file_system_access', 'network_request']
        privileged_users = ['admin@company.com', 'security@company.com']
        
        if tool_name in high_privilege_tools:
            return user_id in privileged_users
        
        return True  # Default allow for standard tools
    
    def _check_excessive_usage(self, user_id: str, server_name: str) -> bool:
        """Check for excessive usage patterns"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check usage in last hour
        one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        
        cursor.execute('''
            SELECT COUNT(*) FROM mcp_usage_events 
            WHERE user_id = ? AND server_name = ? AND timestamp > ?
        ''', (user_id, server_name, one_hour_ago))
        
        usage_count = cursor.fetchone()[0]
        conn.close()
        
        # Threshold: more than 100 requests per hour
        return usage_count > 100
    
    def _generate_security_alert(self, event: MCPUsageEvent, violations: List[str]):
        """Generate security alert for MCP violations"""
        alert = {
            'alert_type': 'mcp_security_violation',
            'timestamp': datetime.utcnow().isoformat(),
            'severity': 'high' if 'sensitive_data_exposure' in violations else 'medium',
            'user_id': event.user_id,
            'server_name': event.server_name,
            'tool_name': event.tool_name,
            'violations': violations,
            'event_details': asdict(event)
        }
        
        # Send to monitoring system (integrate with your existing alert system)
        self._send_to_monitoring_system(alert)
    
    def _send_to_monitoring_system(self, alert: Dict):
        """Send alert to external monitoring system"""
        # Integrate with Sumo Logic, Rapid7, etc.
        print(f"MCP Security Alert: {json.dumps(alert, indent=2)}")

class MCPServerMonitor:
    """Monitor MCP servers for availability, performance, and security"""
    
    def __init__(self, db_path: str = "mcp_usage.db"):
        self.db_path = db_path
        self.monitored_servers = {}
    
    def register_server(self, server_config: Dict):
        """Register MCP server for monitoring"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO mcp_servers 
            (server_name, server_type, endpoint, capabilities, security_level, approved, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            server_config['name'],
            server_config['type'],
            server_config.get('endpoint', ''),
            json.dumps(server_config.get('capabilities', [])),
            server_config.get('security_level', 'medium'),
            server_config.get('approved', False),
            datetime.utcnow().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        self.monitored_servers[server_config['name']] = server_config
    
    def monitor_server_health(self, server_name: str) -> Dict:
        """Monitor MCP server health and performance"""
        if server_name not in self.monitored_servers:
            return {'error': 'Server not registered'}
        
        server_config = self.monitored_servers[server_name]
        
        health_metrics = {
            'server_name': server_name,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'unknown',
            'response_time_ms': 0,
            'cpu_usage': 0,
            'memory_usage': 0,
            'active_connections': 0,
            'error_rate': 0
        }
        
        try:
            # Check server process if local
            if server_config.get('process_name'):
                process_metrics = self._get_process_metrics(server_config['process_name'])
                health_metrics.update(process_metrics)
            
            # Check network connectivity if remote
            if server_config.get('endpoint'):
                network_metrics = self._check_network_connectivity(server_config['endpoint'])
                health_metrics.update(network_metrics)
            
            # Calculate error rate from recent events
            error_rate = self._calculate_error_rate(server_name)
            health_metrics['error_rate'] = error_rate
            
            # Determine overall status
            if health_metrics['response_time_ms'] > 5000 or error_rate > 0.1:
                health_metrics['status'] = 'degraded'
            elif health_metrics['response_time_ms'] > 10000 or error_rate > 0.2:
                health_metrics['status'] = 'unhealthy'
            else:
                health_metrics['status'] = 'healthy'
            
        except Exception as e:
            health_metrics['status'] = 'error'
            health_metrics['error'] = str(e)
        
        return health_metrics
    
    def _get_process_metrics(self, process_name: str) -> Dict:
        """Get process metrics for local MCP server"""
        metrics = {'cpu_usage': 0, 'memory_usage': 0, 'status': 'not_found'}
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                if process_name in proc.info['name']:
                    metrics['cpu_usage'] = proc.info['cpu_percent']
                    metrics['memory_usage'] = proc.info['memory_percent']
                    metrics['status'] = 'running'
                    break
        except Exception as e:
            metrics['error'] = str(e)
        
        return metrics
    
    def _check_network_connectivity(self, endpoint: str) -> Dict:
        """Check network connectivity to remote MCP server"""
        import socket
        import time
        
        metrics = {'response_time_ms': 0, 'status': 'unreachable'}
        
        try:
            # Parse endpoint
            if '://' in endpoint:
                host = endpoint.split('://')[1].split('/')[0].split(':')[0]
                port = int(endpoint.split(':')[-1].split('/')[0]) if ':' in endpoint.split('://')[1] else 80
            else:
                host, port = endpoint.split(':') if ':' in endpoint else (endpoint, 80)
                port = int(port)
            
            # Test connection
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            response_time = (time.time() - start_time) * 1000
            
            if result == 0:
                metrics['response_time_ms'] = response_time
                metrics['status'] = 'reachable'
            
        except Exception as e:
            metrics['error'] = str(e)
        
        return metrics
    
    def _calculate_error_rate(self, server_name: str) -> float:
        """Calculate error rate for MCP server"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get events from last hour
        one_hour_ago = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        
        cursor.execute('''
            SELECT COUNT(*) as total, 
                   SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as errors
            FROM mcp_usage_events 
            WHERE server_name = ? AND timestamp > ?
        ''', (server_name, one_hour_ago))
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0] > 0:
            return result[1] / result[0]
        
        return 0.0

class MCPClientMonitor:
    """Monitor MCP clients for usage patterns and compliance"""
    
    def __init__(self, db_path: str = "mcp_usage.db"):
        self.db_path = db_path
    
    def register_client(self, client_config: Dict):
        """Register MCP client for monitoring"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO mcp_clients 
            (client_name, client_version, user_id, department, approved, last_activity)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            client_config['name'],
            client_config.get('version', 'unknown'),
            client_config['user_id'],
            client_config.get('department', 'unknown'),
            client_config.get('approved', False),
            datetime.utcnow().isoformat()
        ))
        
        conn.commit()
        conn.close()
    
    def analyze_client_behavior(self, client_name: str, days: int = 7) -> Dict:
        """Analyze MCP client usage behavior"""
        conn = sqlite3.connect(self.db_path)
        
        # Get client usage data
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        usage_df = pd.read_sql_query('''
            SELECT * FROM mcp_usage_events 
            WHERE client_name = ? AND timestamp >= ?
            ORDER BY timestamp
        ''', conn, params=(client_name, start_date))
        
        conn.close()
        
        if len(usage_df) == 0:
            return {'client_name': client_name, 'no_data': True}
        
        # Analyze usage patterns
        analysis = {
            'client_name': client_name,
            'analysis_period_days': days,
            'total_requests': len(usage_df),
            'unique_servers': usage_df['server_name'].nunique(),
            'unique_tools': usage_df['tool_name'].nunique(),
            'success_rate': usage_df['success'].mean(),
            'avg_response_time_ms': usage_df['execution_time_ms'].mean(),
            'high_risk_requests': len(usage_df[usage_df['risk_level'] == 'high']),
            'sensitive_data_incidents': len(usage_df[usage_df['sensitive_data_detected'] == True]),
            'most_used_servers': usage_df['server_name'].value_counts().head(5).to_dict(),
            'most_used_tools': usage_df['tool_name'].value_counts().head(5).to_dict(),
            'usage_by_hour': self._analyze_usage_by_hour(usage_df),
            'risk_assessment': self._assess_client_risk(usage_df)
        }
        
        return analysis
    
    def _analyze_usage_by_hour(self, usage_df) -> Dict:
        """Analyze usage patterns by hour of day"""
        try:
            usage_df['hour'] = pd.to_datetime(usage_df['timestamp']).dt.hour
            hourly_usage = usage_df.groupby('hour').size().to_dict()
            
            # Find peak usage hours
            peak_hour = max(hourly_usage, key=hourly_usage.get) if hourly_usage else 0
            
            return {
                'hourly_distribution': hourly_usage,
                'peak_hour': peak_hour,
                'peak_usage_count': hourly_usage.get(peak_hour, 0)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _assess_client_risk(self, usage_df) -> Dict:
        """Assess risk level of MCP client based on usage patterns"""
        risk_factors = []
        risk_score = 0
        
        # High volume usage
        if len(usage_df) > 1000:
            risk_factors.append('high_volume_usage')
            risk_score += 2
        
        # High error rate
        error_rate = 1 - usage_df['success'].mean()
        if error_rate > 0.1:
            risk_factors.append('high_error_rate')
            risk_score += 3
        
        # Sensitive data exposure
        sensitive_incidents = len(usage_df[usage_df['sensitive_data_detected'] == True])
        if sensitive_incidents > 0:
            risk_factors.append('sensitive_data_exposure')
            risk_score += 5
        
        # Unusual usage patterns (e.g., usage outside business hours)
        usage_df['hour'] = pd.to_datetime(usage_df['timestamp']).dt.hour
        after_hours_usage = len(usage_df[(usage_df['hour'] < 8) | (usage_df['hour'] > 18)])
        if after_hours_usage > len(usage_df) * 0.3:  # More than 30% after hours
            risk_factors.append('unusual_timing')
            risk_score += 2
        
        # Multiple server usage
        if usage_df['server_name'].nunique() > 5:
            risk_factors.append('multiple_server_usage')
            risk_score += 1
        
        # Determine risk level
        if risk_score >= 8:
            risk_level = 'critical'
        elif risk_score >= 5:
            risk_level = 'high'
        elif risk_score >= 2:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'risk_level': risk_level,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'recommendations': self._get_risk_recommendations(risk_factors)
        }
    
    def _get_risk_recommendations(self, risk_factors: List[str]) -> List[str]:
        """Get recommendations based on risk factors"""
        recommendations = []
        
        if 'high_volume_usage' in risk_factors:
            recommendations.append('Review usage patterns and implement rate limiting')
        
        if 'high_error_rate' in risk_factors:
            recommendations.append('Investigate error causes and improve error handling')
        
        if 'sensitive_data_exposure' in risk_factors:
            recommendations.append('Implement data loss prevention controls')
        
        if 'unusual_timing' in risk_factors:
            recommendations.append('Review after-hours usage and implement time-based restrictions')
        
        if 'multiple_server_usage' in risk_factors:
            recommendations.append('Audit server access permissions and implement least privilege')
        
        return recommendations

class MCPComplianceReporter:
    """Generate compliance reports for MCP usage"""
    
    def __init__(self, db_path: str = "mcp_usage.db"):
        self.db_path = db_path
    
    def generate_usage_report(self, start_date: str, end_date: str) -> Dict:
        """Generate comprehensive MCP usage report"""
        conn = sqlite3.connect(self.db_path)
        
        # Get usage data for period
        usage_df = pd.read_sql_query('''
            SELECT * FROM mcp_usage_events 
            WHERE timestamp BETWEEN ? AND ?
        ''', conn, params=(start_date, end_date))
        
        # Get server and client data
        servers_df = pd.read_sql_query('SELECT * FROM mcp_servers', conn)
        clients_df = pd.read_sql_query('SELECT * FROM mcp_clients', conn)
        
        conn.close()
        
        report = {
            'report_period': f"{start_date} to {end_date}",
            'summary': {
                'total_requests': len(usage_df),
                'unique_users': usage_df['user_id'].nunique() if len(usage_df) > 0 else 0,
                'unique_servers': usage_df['server_name'].nunique() if len(usage_df) > 0 else 0,
                'unique_clients': usage_df['client_name'].nunique() if len(usage_df) > 0 else 0,
                'success_rate': usage_df['success'].mean() if len(usage_df) > 0 else 0,
                'avg_response_time_ms': usage_df['execution_time_ms'].mean() if len(usage_df) > 0 else 0
            },
            'security_metrics': {
                'high_risk_requests': len(usage_df[usage_df['risk_level'] == 'high']) if len(usage_df) > 0 else 0,
                'sensitive_data_incidents': len(usage_df[usage_df['sensitive_data_detected'] == True]) if len(usage_df) > 0 else 0,
                'unauthorized_server_usage': len(usage_df[~usage_df['server_name'].isin(servers_df[servers_df['approved'] == True]['server_name'])]) if len(usage_df) > 0 else 0,
                'error_incidents': len(usage_df[usage_df['success'] == False]) if len(usage_df) > 0 else 0
            },
            'compliance_status': self._assess_compliance_status(usage_df, servers_df, clients_df),
            'top_users': usage_df['user_id'].value_counts().head(10).to_dict() if len(usage_df) > 0 else {},
            'top_servers': usage_df['server_name'].value_counts().head(10).to_dict() if len(usage_df) > 0 else {},
            'top_tools': usage_df['tool_name'].value_counts().head(10).to_dict() if len(usage_df) > 0 else {},
            'recommendations': self._generate_recommendations(usage_df, servers_df, clients_df)
        }
        
        return report
    
    def _assess_compliance_status(self, usage_df, servers_df, clients_df) -> Dict:
        """Assess overall compliance status"""
        compliance = {
            'overall_status': 'compliant',
            'issues': [],
            'score': 100
        }
        
        if len(usage_df) == 0:
            return compliance
        
        # Check for unauthorized servers
        approved_servers = set(servers_df[servers_df['approved'] == True]['server_name'])
        unauthorized_usage = usage_df[~usage_df['server_name'].isin(approved_servers)]
        
        if len(unauthorized_usage) > 0:
            compliance['issues'].append(f"{len(unauthorized_usage)} requests to unauthorized servers")
            compliance['score'] -= 20
        
        # Check for sensitive data exposure
        sensitive_incidents = len(usage_df[usage_df['sensitive_data_detected'] == True])
        if sensitive_incidents > 0:
            compliance['issues'].append(f"{sensitive_incidents} sensitive data exposure incidents")
            compliance['score'] -= 30
        
        # Check error rate
        error_rate = 1 - usage_df['success'].mean()
        if error_rate > 0.05:  # More than 5% error rate
            compliance['issues'].append(f"High error rate: {error_rate:.2%}")
            compliance['score'] -= 10
        
        # Determine overall status
        if compliance['score'] < 70:
            compliance['overall_status'] = 'non_compliant'
        elif compliance['score'] < 90:
            compliance['overall_status'] = 'partially_compliant'
        
        return compliance
    
    def _generate_recommendations(self, usage_df, servers_df, clients_df) -> List[str]:
        """Generate recommendations based on usage analysis"""
        recommendations = []
        
        if len(usage_df) == 0:
            recommendations.append("No MCP usage detected - consider deployment and adoption strategies")
            return recommendations
        
        # Server approval recommendations
        unapproved_servers = servers_df[servers_df['approved'] == False]['server_name'].tolist()
        if unapproved_servers:
            recommendations.append(f"Review and approve {len(unapproved_servers)} pending MCP servers")
        
        # Client approval recommendations
        unapproved_clients = clients_df[clients_df['approved'] == False]['client_name'].tolist()
        if unapproved_clients:
            recommendations.append(f"Review and approve {len(unapproved_clients)} pending MCP clients")
        
        # Usage pattern recommendations
        high_volume_users = usage_df['user_id'].value_counts()
        if len(high_volume_users) > 0 and high_volume_users.iloc[0] > 1000:
            recommendations.append("Implement rate limiting for high-volume users")
        
        # Security recommendations
        if len(usage_df[usage_df['sensitive_data_detected'] == True]) > 0:
            recommendations.append("Implement data loss prevention controls for MCP communications")
        
        # Performance recommendations
        avg_response_time = usage_df['execution_time_ms'].mean()
        if avg_response_time > 5000:  # More than 5 seconds
            recommendations.append("Investigate and optimize MCP server performance")
        
        return recommendations

# Usage Example and Integration
if __name__ == "__main__":
    import pandas as pd
    
    # Initialize MCP monitoring system
    protocol_monitor = MCPProtocolMonitor()
    server_monitor = MCPServerMonitor()
    client_monitor = MCPClientMonitor()
    compliance_reporter = MCPComplianceReporter()
    
    # Register MCP servers
    server_monitor.register_server({
        'name': 'filesystem-server',
        'type': 'local',
        'capabilities': ['file_read', 'file_write', 'directory_list'],
        'security_level': 'high',
        'approved': True,
        'process_name': 'mcp-filesystem'
    })
    
    server_monitor.register_server({
        'name': 'database-server',
        'type': 'remote',
        'endpoint': 'localhost:8080',
        'capabilities': ['query', 'insert', 'update'],
        'security_level': 'critical',
        'approved': True
    })
    
    # Register MCP clients
    client_monitor.register_client({
        'name': 'claude-desktop',
        'version': '1.0.0',
        'user_id': 'john.doe@company.com',
        'department': 'Engineering',
        'approved': True
    })
    
    # Example: Monitor MCP message
    sample_message = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'tools/call',
        'params': {
            'name': 'read_file',
            'arguments': {
                'path': '/home/user/documents/report.pdf'
            }
        }
    }
    
    session_context = {
        'session_id': 'session_123',
        'user_id': 'john.doe@company.com',
        'client_name': 'claude-desktop',
        'server_name': 'filesystem-server',
        'source_ip': '192.168.1.100',
        'user_agent': 'Claude Desktop/1.0.0'
    }
    
    # Intercept and monitor the message
    monitored_message = protocol_monitor.intercept_mcp_message(
        sample_message, 'request', session_context
    )
    
    # Generate compliance report
    start_date = (datetime.utcnow() - timedelta(days=30)).isoformat()
    end_date = datetime.utcnow().isoformat()
    
    report = compliance_reporter.generate_usage_report(start_date, end_date)
    print("MCP Compliance Report:", json.dumps(report, indent=2))