"""
MCP Usage Monitoring Integration Examples
Real-world implementations for monitoring Model Context Protocol usage
"""

import json
import asyncio
import websockets
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import threading
import queue
import logging
from pathlib import Path
import subprocess
import psutil
import requests

class MCPProxyMonitor:
    """Proxy-based MCP monitoring that intercepts all MCP communications"""
    
    def __init__(self, target_host: str = "localhost", target_port: int = 8080, 
                 proxy_port: int = 8081, db_path: str = "mcp_usage.db"):
        self.target_host = target_host
        self.target_port = target_port
        self.proxy_port = proxy_port
        self.db_path = db_path
        self.active_connections = {}
        self.monitoring_active = False
        
    async def start_proxy(self):
        """Start MCP proxy server for monitoring"""
        self.monitoring_active = True
        
        async def handle_client(websocket, path):
            client_id = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
            
            try:
                # Connect to actual MCP server
                target_uri = f"ws://{self.target_host}:{self.target_port}{path}"
                
                async with websockets.connect(target_uri) as target_ws:
                    self.active_connections[client_id] = {
                        'client_ws': websocket,
                        'target_ws': target_ws,
                        'start_time': datetime.utcnow(),
                        'message_count': 0
                    }
                    
                    # Handle bidirectional communication with monitoring
                    await asyncio.gather(
                        self._forward_messages(websocket, target_ws, 'client_to_server', client_id),
                        self._forward_messages(target_ws, websocket, 'server_to_client', client_id)
                    )
                    
            except Exception as e:
                logging.error(f"Proxy error for client {client_id}: {e}")
            finally:
                if client_id in self.active_connections:
                    del self.active_connections[client_id]
        
        # Start proxy server
        server = await websockets.serve(handle_client, "localhost", self.proxy_port)
        logging.info(f"MCP Proxy started on port {self.proxy_port}, forwarding to {self.target_host}:{self.target_port}")
        
        await server.wait_closed()
    
    async def _forward_messages(self, source_ws, target_ws, direction: str, client_id: str):
        """Forward messages between client and server with monitoring"""
        
        try:
            async for message in source_ws:
                # Monitor the message
                await self._monitor_message(message, direction, client_id)
                
                # Forward to target
                await target_ws.send(message)
                
                # Update connection stats
                if client_id in self.active_connections:
                    self.active_connections[client_id]['message_count'] += 1
                    
        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            logging.error(f"Message forwarding error: {e}")
    
    async def _monitor_message(self, message: str, direction: str, client_id: str):
        """Monitor and analyze MCP message"""
        
        try:
            # Parse JSON-RPC message
            msg_data = json.loads(message)
            
            # Extract monitoring data
            monitoring_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'client_id': client_id,
                'direction': direction,
                'message_type': msg_data.get('method', 'response'),
                'message_id': msg_data.get('id'),
                'message_size': len(message),
                'has_error': 'error' in msg_data,
                'method': msg_data.get('method'),
                'params': msg_data.get('params', {}),
                'result': msg_data.get('result'),
                'error': msg_data.get('error')
            }
            
            # Analyze for security and compliance
            security_analysis = self._analyze_message_security(msg_data)
            monitoring_data.update(security_analysis)
            
            # Store in database
            self._store_monitoring_data(monitoring_data)
            
            # Generate alerts if needed
            if security_analysis.get('risk_level') == 'high':
                await self._generate_alert(monitoring_data)
                
        except json.JSONDecodeError:
            # Handle non-JSON messages
            logging.warning(f"Non-JSON message received: {message[:100]}...")
        except Exception as e:
            logging.error(f"Message monitoring error: {e}")
    
    def _analyze_message_security(self, msg_data: Dict) -> Dict:
        """Analyze MCP message for security risks"""
        
        analysis = {
            'risk_level': 'low',
            'sensitive_data_detected': False,
            'policy_violations': [],
            'compliance_tags': []
        }
        
        method = msg_data.get('method', '')
        params = msg_data.get('params', {})
        
        # Check for high-risk methods
        high_risk_methods = ['tools/call', 'resources/write', 'prompts/execute']
        if method in high_risk_methods:
            analysis['risk_level'] = 'high'
            analysis['compliance_tags'].append('high_risk_operation')
        
        # Check for sensitive data patterns
        message_str = json.dumps(msg_data).lower()
        sensitive_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',  # Credit card
            r'\bpassword\b', r'\bapi[_-]?key\b', r'\btoken\b'  # Credentials
        ]
        
        import re
        for pattern in sensitive_patterns:
            if re.search(pattern, message_str):
                analysis['sensitive_data_detected'] = True
                analysis['risk_level'] = 'high'
                analysis['policy_violations'].append('sensitive_data_exposure')
                break
        
        # Check for unauthorized tool usage
        if method == 'tools/call':
            tool_name = params.get('name', '')
            restricted_tools = ['database_query', 'file_system_write', 'network_request']
            
            if tool_name in restricted_tools:
                analysis['policy_violations'].append('restricted_tool_usage')
                analysis['compliance_tags'].append('requires_authorization')
        
        return analysis
    
    def _store_monitoring_data(self, data: Dict):
        """Store monitoring data in database"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mcp_proxy_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                message_type TEXT,
                message_id TEXT,
                message_size INTEGER,
                has_error BOOLEAN,
                method TEXT,
                params TEXT,
                result TEXT,
                error_info TEXT,
                risk_level TEXT,
                sensitive_data_detected BOOLEAN,
                policy_violations TEXT,
                compliance_tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO mcp_proxy_logs 
            (timestamp, client_id, direction, message_type, message_id, message_size,
             has_error, method, params, result, error_info, risk_level, 
             sensitive_data_detected, policy_violations, compliance_tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['timestamp'], data['client_id'], data['direction'],
            data['message_type'], data['message_id'], data['message_size'],
            data['has_error'], data['method'], 
            json.dumps(data['params']), json.dumps(data.get('result')),
            json.dumps(data.get('error')), data['risk_level'],
            data['sensitive_data_detected'], json.dumps(data['policy_violations']),
            json.dumps(data['compliance_tags'])
        ))
        
        conn.commit()
        conn.close()
    
    async def _generate_alert(self, monitoring_data: Dict):
        """Generate security alert for high-risk MCP usage"""
        
        alert = {
            'alert_type': 'mcp_security_risk',
            'timestamp': datetime.utcnow().isoformat(),
            'severity': 'high',
            'client_id': monitoring_data['client_id'],
            'method': monitoring_data['method'],
            'risk_level': monitoring_data['risk_level'],
            'policy_violations': monitoring_data['policy_violations'],
            'sensitive_data_detected': monitoring_data['sensitive_data_detected'],
            'message_details': {
                'direction': monitoring_data['direction'],
                'message_type': monitoring_data['message_type'],
                'message_size': monitoring_data['message_size']
            }
        }
        
        # Send to monitoring system (integrate with existing alert system)
        await self._send_alert_to_monitoring_system(alert)
    
    async def _send_alert_to_monitoring_system(self, alert: Dict):
        """Send alert to external monitoring system"""
        
        # Example integration with Sumo Logic
        try:
            # This would integrate with your existing monitoring system
            print(f"MCP Security Alert: {json.dumps(alert, indent=2)}")
            
            # Example: Send to webhook or API
            # requests.post('https://your-monitoring-webhook.com/alerts', json=alert)
            
        except Exception as e:
            logging.error(f"Failed to send MCP alert: {e}")

class MCPConfigurationMonitor:
    """Monitor MCP configuration files and server deployments"""
    
    def __init__(self, config_paths: List[str], db_path: str = "mcp_usage.db"):
        self.config_paths = config_paths
        self.db_path = db_path
        self.file_watchers = {}
        self.monitoring_active = False
    
    def start_monitoring(self):
        """Start monitoring MCP configuration files"""
        
        self.monitoring_active = True
        
        # Monitor each configuration path
        for config_path in self.config_paths:
            if Path(config_path).exists():
                self._start_file_watcher(config_path)
                self._analyze_current_config(config_path)
    
    def _start_file_watcher(self, config_path: str):
        """Start file watcher for MCP configuration"""
        
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
            
            class MCPConfigHandler(FileSystemEventHandler):
                def __init__(self, monitor):
                    self.monitor = monitor
                
                def on_modified(self, event):
                    if not event.is_directory and event.src_path.endswith('.json'):
                        self.monitor._handle_config_change(event.src_path)
            
            observer = Observer()
            observer.schedule(MCPConfigHandler(self), config_path, recursive=True)
            observer.start()
            
            self.file_watchers[config_path] = observer
            
        except ImportError:
            logging.warning("watchdog not installed - file monitoring disabled")
        except Exception as e:
            logging.error(f"Failed to start file watcher for {config_path}: {e}")
    
    def _handle_config_change(self, file_path: str):
        """Handle MCP configuration file changes"""
        
        try:
            # Analyze the changed configuration
            config_analysis = self._analyze_config_file(file_path)
            
            # Store configuration change event
            change_event = {
                'timestamp': datetime.utcnow().isoformat(),
                'file_path': file_path,
                'change_type': 'modification',
                'analysis': config_analysis
            }
            
            self._store_config_event(change_event)
            
            # Check for security issues
            if config_analysis.get('security_issues'):
                self._generate_config_alert(change_event)
                
        except Exception as e:
            logging.error(f"Error handling config change for {file_path}: {e}")
    
    def _analyze_config_file(self, file_path: str) -> Dict:
        """Analyze MCP configuration file for security and compliance"""
        
        analysis = {
            'file_path': file_path,
            'servers_count': 0,
            'approved_servers': 0,
            'security_issues': [],
            'compliance_issues': [],
            'recommendations': []
        }
        
        try:
            with open(file_path, 'r') as f:
                config = json.load(f)
            
            # Analyze MCP servers configuration
            mcp_servers = config.get('mcpServers', {})
            analysis['servers_count'] = len(mcp_servers)
            
            for server_name, server_config in mcp_servers.items():
                # Check for security issues
                if not server_config.get('disabled', False):
                    # Check for insecure configurations
                    command = server_config.get('command', '')
                    args = server_config.get('args', [])
                    
                    # Check for potentially dangerous commands
                    dangerous_commands = ['curl', 'wget', 'python', 'node', 'bash', 'sh']
                    if any(cmd in command for cmd in dangerous_commands):
                        analysis['security_issues'].append(f"Potentially dangerous command in {server_name}: {command}")
                    
                    # Check for external network access
                    if any('http' in str(arg) for arg in args):
                        analysis['security_issues'].append(f"External network access detected in {server_name}")
                    
                    # Check for file system access
                    if any('file://' in str(arg) or '/' in str(arg) for arg in args):
                        analysis['security_issues'].append(f"File system access detected in {server_name}")
                    
                    # Check environment variables for secrets
                    env_vars = server_config.get('env', {})
                    for env_name, env_value in env_vars.items():
                        if any(keyword in env_name.lower() for keyword in ['key', 'token', 'password', 'secret']):
                            if env_value and not env_value.startswith('${'):  # Not a reference
                                analysis['security_issues'].append(f"Hardcoded secret in {server_name}: {env_name}")
                    
                    # Check auto-approval settings
                    auto_approve = server_config.get('autoApprove', [])
                    if auto_approve:
                        if '*' in auto_approve or 'all' in auto_approve:
                            analysis['security_issues'].append(f"Overly permissive auto-approval in {server_name}")
                        elif len(auto_approve) > 10:
                            analysis['compliance_issues'].append(f"Excessive auto-approvals in {server_name}: {len(auto_approve)} tools")
                
                else:
                    analysis['approved_servers'] += 1
            
            # Generate recommendations
            if analysis['security_issues']:
                analysis['recommendations'].append("Review and remediate security issues in MCP server configurations")
            
            if analysis['servers_count'] > 10:
                analysis['recommendations'].append("Consider consolidating MCP servers to reduce attack surface")
            
            if analysis['approved_servers'] / analysis['servers_count'] < 0.8:
                analysis['recommendations'].append("Review and approve pending MCP servers")
                
        except json.JSONDecodeError:
            analysis['security_issues'].append("Invalid JSON configuration file")
        except Exception as e:
            analysis['security_issues'].append(f"Configuration analysis error: {str(e)}")
        
        return analysis
    
    def _analyze_current_config(self, config_path: str):
        """Analyze current MCP configuration"""
        
        if Path(config_path).is_file():
            # Single file
            analysis = self._analyze_config_file(config_path)
            
            config_event = {
                'timestamp': datetime.utcnow().isoformat(),
                'file_path': config_path,
                'change_type': 'initial_scan',
                'analysis': analysis
            }
            
            self._store_config_event(config_event)
            
        elif Path(config_path).is_dir():
            # Directory - scan all JSON files
            for json_file in Path(config_path).glob('**/*.json'):
                if 'mcp' in json_file.name.lower():
                    analysis = self._analyze_config_file(str(json_file))
                    
                    config_event = {
                        'timestamp': datetime.utcnow().isoformat(),
                        'file_path': str(json_file),
                        'change_type': 'initial_scan',
                        'analysis': analysis
                    }
                    
                    self._store_config_event(config_event)
    
    def _store_config_event(self, event: Dict):
        """Store configuration event in database"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mcp_config_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                file_path TEXT NOT NULL,
                change_type TEXT NOT NULL,
                servers_count INTEGER DEFAULT 0,
                approved_servers INTEGER DEFAULT 0,
                security_issues TEXT,
                compliance_issues TEXT,
                recommendations TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        analysis = event['analysis']
        
        cursor.execute('''
            INSERT INTO mcp_config_events 
            (timestamp, file_path, change_type, servers_count, approved_servers,
             security_issues, compliance_issues, recommendations)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event['timestamp'], event['file_path'], event['change_type'],
            analysis['servers_count'], analysis['approved_servers'],
            json.dumps(analysis['security_issues']),
            json.dumps(analysis['compliance_issues']),
            json.dumps(analysis['recommendations'])
        ))
        
        conn.commit()
        conn.close()
    
    def _generate_config_alert(self, event: Dict):
        """Generate alert for configuration security issues"""
        
        alert = {
            'alert_type': 'mcp_config_security',
            'timestamp': datetime.utcnow().isoformat(),
            'severity': 'medium',
            'file_path': event['file_path'],
            'security_issues': event['analysis']['security_issues'],
            'compliance_issues': event['analysis']['compliance_issues'],
            'recommendations': event['analysis']['recommendations']
        }
        
        # Send to monitoring system
        print(f"MCP Configuration Alert: {json.dumps(alert, indent=2)}")

class MCPProcessMonitor:
    """Monitor MCP server processes for performance and security"""
    
    def __init__(self, db_path: str = "mcp_usage.db"):
        self.db_path = db_path
        self.monitored_processes = {}
        self.monitoring_active = False
    
    def start_monitoring(self):
        """Start monitoring MCP server processes"""
        
        self.monitoring_active = True
        
        # Start background monitoring thread
        monitoring_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        monitoring_thread.start()
    
    def register_process(self, process_config: Dict):
        """Register MCP server process for monitoring"""
        
        self.monitored_processes[process_config['name']] = {
            'config': process_config,
            'last_seen': None,
            'metrics_history': []
        }
    
    def _monitor_processes(self):
        """Background process monitoring loop"""
        
        while self.monitoring_active:
            try:
                for process_name, process_info in self.monitored_processes.items():
                    metrics = self._collect_process_metrics(process_name, process_info['config'])
                    
                    if metrics:
                        # Store metrics
                        self._store_process_metrics(process_name, metrics)
                        
                        # Update process info
                        process_info['last_seen'] = datetime.utcnow()
                        process_info['metrics_history'].append(metrics)
                        
                        # Keep only last 100 metrics
                        if len(process_info['metrics_history']) > 100:
                            process_info['metrics_history'] = process_info['metrics_history'][-100:]
                        
                        # Check for anomalies
                        self._check_process_anomalies(process_name, metrics, process_info['metrics_history'])
                
                # Sleep for monitoring interval
                time.sleep(30)  # Monitor every 30 seconds
                
            except Exception as e:
                logging.error(f"Process monitoring error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _collect_process_metrics(self, process_name: str, config: Dict) -> Optional[Dict]:
        """Collect metrics for MCP server process"""
        
        try:
            # Find process by name or command
            target_processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_info', 'connections']):
                try:
                    # Check if this is our MCP server process
                    if (config.get('process_name') and config['process_name'] in proc.info['name']) or \
                       (config.get('command') and any(config['command'] in cmd for cmd in proc.info['cmdline'])):
                        target_processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if not target_processes:
                return None
            
            # Collect metrics from all matching processes
            total_cpu = 0
            total_memory = 0
            total_connections = 0
            process_count = len(target_processes)
            
            for proc in target_processes:
                try:
                    total_cpu += proc.cpu_percent()
                    total_memory += proc.memory_info().rss
                    total_connections += len(proc.connections())
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            metrics = {
                'timestamp': datetime.utcnow().isoformat(),
                'process_count': process_count,
                'cpu_percent': total_cpu,
                'memory_mb': total_memory / (1024 * 1024),
                'connection_count': total_connections,
                'status': 'running' if process_count > 0 else 'stopped'
            }
            
            return metrics
            
        except Exception as e:
            logging.error(f"Error collecting metrics for {process_name}: {e}")
            return None
    
    def _store_process_metrics(self, process_name: str, metrics: Dict):
        """Store process metrics in database"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mcp_process_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                process_name TEXT NOT NULL,
                process_count INTEGER DEFAULT 0,
                cpu_percent REAL DEFAULT 0,
                memory_mb REAL DEFAULT 0,
                connection_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'unknown',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO mcp_process_metrics 
            (timestamp, process_name, process_count, cpu_percent, memory_mb, connection_count, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics['timestamp'], process_name, metrics['process_count'],
            metrics['cpu_percent'], metrics['memory_mb'], 
            metrics['connection_count'], metrics['status']
        ))
        
        conn.commit()
        conn.close()
    
    def _check_process_anomalies(self, process_name: str, current_metrics: Dict, history: List[Dict]):
        """Check for process anomalies and generate alerts"""
        
        if len(history) < 10:  # Need enough history for comparison
            return
        
        # Calculate baseline metrics from history
        recent_history = history[-10:]  # Last 10 measurements
        
        avg_cpu = sum(m['cpu_percent'] for m in recent_history) / len(recent_history)
        avg_memory = sum(m['memory_mb'] for m in recent_history) / len(recent_history)
        avg_connections = sum(m['connection_count'] for m in recent_history) / len(recent_history)
        
        anomalies = []
        
        # Check for CPU anomalies
        if current_metrics['cpu_percent'] > avg_cpu * 2 and current_metrics['cpu_percent'] > 50:
            anomalies.append(f"High CPU usage: {current_metrics['cpu_percent']:.1f}% (avg: {avg_cpu:.1f}%)")
        
        # Check for memory anomalies
        if current_metrics['memory_mb'] > avg_memory * 1.5 and current_metrics['memory_mb'] > 100:
            anomalies.append(f"High memory usage: {current_metrics['memory_mb']:.1f}MB (avg: {avg_memory:.1f}MB)")
        
        # Check for connection anomalies
        if current_metrics['connection_count'] > avg_connections * 2 and current_metrics['connection_count'] > 10:
            anomalies.append(f"High connection count: {current_metrics['connection_count']} (avg: {avg_connections:.1f})")
        
        # Check for process crashes
        if current_metrics['process_count'] == 0:
            anomalies.append("Process not running - potential crash or shutdown")
        
        # Generate alert if anomalies detected
        if anomalies:
            alert = {
                'alert_type': 'mcp_process_anomaly',
                'timestamp': datetime.utcnow().isoformat(),
                'severity': 'medium',
                'process_name': process_name,
                'anomalies': anomalies,
                'current_metrics': current_metrics,
                'baseline_metrics': {
                    'avg_cpu': avg_cpu,
                    'avg_memory': avg_memory,
                    'avg_connections': avg_connections
                }
            }
            
            print(f"MCP Process Alert: {json.dumps(alert, indent=2)}")

# Integration with existing monitoring system
class MCPMonitoringIntegration:
    """Integration layer for MCP monitoring with existing systems"""
    
    def __init__(self, sumo_config: Dict, rapid7_config: Dict, jira_config: Dict):
        self.sumo_config = sumo_config
        self.rapid7_config = rapid7_config
        self.jira_config = jira_config
        
        # Initialize MCP monitoring components
        self.proxy_monitor = MCPProxyMonitor()
        self.config_monitor = MCPConfigurationMonitor([
            "~/.kiro/settings/mcp.json",
            "/etc/mcp/",
            "./mcp.json"
        ])
        self.process_monitor = MCPProcessMonitor()
    
    def start_comprehensive_monitoring(self):
        """Start all MCP monitoring components"""
        
        # Start configuration monitoring
        self.config_monitor.start_monitoring()
        
        # Start process monitoring
        self.process_monitor.start_monitoring()
        
        # Register common MCP servers for process monitoring
        common_servers = [
            {
                'name': 'filesystem-server',
                'process_name': 'mcp-filesystem',
                'command': 'uvx mcp-filesystem'
            },
            {
                'name': 'database-server', 
                'process_name': 'mcp-database',
                'command': 'uvx mcp-database'
            },
            {
                'name': 'web-server',
                'process_name': 'mcp-web',
                'command': 'uvx mcp-web'
            }
        ]
        
        for server in common_servers:
            self.process_monitor.register_process(server)
        
        print("MCP comprehensive monitoring started")
    
    def generate_mcp_compliance_report(self, days: int = 30) -> Dict:
        """Generate comprehensive MCP compliance report"""
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        conn = sqlite3.connect("mcp_usage.db")
        
        # Get MCP usage statistics
        usage_stats = pd.read_sql_query('''
            SELECT COUNT(*) as total_messages,
                   COUNT(DISTINCT client_id) as unique_clients,
                   AVG(message_size) as avg_message_size,
                   SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_risk_messages,
                   SUM(CASE WHEN sensitive_data_detected = 1 THEN 1 ELSE 0 END) as sensitive_data_incidents
            FROM mcp_proxy_logs 
            WHERE timestamp >= ?
        ''', conn, params=(start_date.isoformat(),))
        
        # Get configuration issues
        config_issues = pd.read_sql_query('''
            SELECT file_path, security_issues, compliance_issues
            FROM mcp_config_events 
            WHERE timestamp >= ?
        ''', conn, params=(start_date.isoformat(),))
        
        # Get process health
        process_health = pd.read_sql_query('''
            SELECT process_name, AVG(cpu_percent) as avg_cpu, AVG(memory_mb) as avg_memory,
                   COUNT(CASE WHEN status = 'stopped' THEN 1 END) as downtime_incidents
            FROM mcp_process_metrics 
            WHERE timestamp >= ?
            GROUP BY process_name
        ''', conn, params=(start_date.isoformat(),))
        
        conn.close()
        
        # Compile report
        report = {
            'report_period': f"{start_date.date()} to {end_date.date()}",
            'usage_summary': usage_stats.iloc[0].to_dict() if len(usage_stats) > 0 else {},
            'security_metrics': {
                'high_risk_percentage': (usage_stats.iloc[0]['high_risk_messages'] / usage_stats.iloc[0]['total_messages'] * 100) if usage_stats.iloc[0]['total_messages'] > 0 else 0,
                'sensitive_data_incidents': usage_stats.iloc[0]['sensitive_data_incidents'] if len(usage_stats) > 0 else 0,
                'configuration_security_issues': len([issue for issues in config_issues['security_issues'] for issue in json.loads(issues) if issues != '[]']),
            },
            'compliance_status': self._assess_mcp_compliance(usage_stats, config_issues, process_health),
            'process_health': process_health.to_dict('records') if len(process_health) > 0 else [],
            'recommendations': self._generate_mcp_recommendations(usage_stats, config_issues, process_health)
        }
        
        return report
    
    def _assess_mcp_compliance(self, usage_stats, config_issues, process_health) -> Dict:
        """Assess MCP compliance status"""
        
        compliance = {
            'overall_status': 'compliant',
            'score': 100,
            'issues': []
        }
        
        if len(usage_stats) > 0:
            stats = usage_stats.iloc[0]
            
            # Check sensitive data exposure
            if stats['sensitive_data_incidents'] > 0:
                compliance['issues'].append(f"{stats['sensitive_data_incidents']} sensitive data exposure incidents")
                compliance['score'] -= 30
            
            # Check high-risk usage
            if stats['total_messages'] > 0:
                high_risk_rate = stats['high_risk_messages'] / stats['total_messages']
                if high_risk_rate > 0.1:  # More than 10% high-risk
                    compliance['issues'].append(f"High-risk usage rate: {high_risk_rate:.1%}")
                    compliance['score'] -= 20
        
        # Check configuration issues
        total_security_issues = sum(len(json.loads(issues)) for issues in config_issues['security_issues'] if issues != '[]')
        if total_security_issues > 0:
            compliance['issues'].append(f"{total_security_issues} configuration security issues")
            compliance['score'] -= 25
        
        # Check process health
        if len(process_health) > 0:
            downtime_incidents = process_health['downtime_incidents'].sum()
            if downtime_incidents > 0:
                compliance['issues'].append(f"{downtime_incidents} process downtime incidents")
                compliance['score'] -= 15
        
        # Determine overall status
        if compliance['score'] < 70:
            compliance['overall_status'] = 'non_compliant'
        elif compliance['score'] < 90:
            compliance['overall_status'] = 'partially_compliant'
        
        return compliance
    
    def _generate_mcp_recommendations(self, usage_stats, config_issues, process_health) -> List[str]:
        """Generate MCP-specific recommendations"""
        
        recommendations = []
        
        if len(usage_stats) > 0:
            stats = usage_stats.iloc[0]
            
            if stats['sensitive_data_incidents'] > 0:
                recommendations.append("Implement data loss prevention controls for MCP communications")
            
            if stats['total_messages'] > 1000:
                recommendations.append("Consider implementing rate limiting for MCP usage")
        
        if len(config_issues) > 0:
            recommendations.append("Review and remediate MCP server configuration security issues")
        
        if len(process_health) > 0:
            avg_cpu = process_health['avg_cpu'].mean()
            if avg_cpu > 50:
                recommendations.append("Optimize MCP server performance - high CPU usage detected")
        
        recommendations.append("Regularly audit MCP server approvals and access controls")
        recommendations.append("Implement monitoring alerts for MCP security violations")
        
        return recommendations

# Usage Example
if __name__ == "__main__":
    import pandas as pd
    import time
    
    # Initialize MCP monitoring integration
    mcp_integration = MCPMonitoringIntegration(
        sumo_config={'endpoint': 'https://collectors.sumologic.com/...'},
        rapid7_config={'api_key': 'your-rapid7-key'},
        jira_config={'url': 'https://company.atlassian.net', 'project': 'MCPSEC'}
    )
    
    # Start comprehensive monitoring
    mcp_integration.start_comprehensive_monitoring()
    
    # Example: Start MCP proxy monitoring (in production, this would run as a service)
    # asyncio.run(mcp_integration.proxy_monitor.start_proxy())
    
    # Generate compliance report
    report = mcp_integration.generate_mcp_compliance_report(30)
    print("MCP Compliance Report:", json.dumps(report, indent=2))