"""
30-Minute Proof of Concept: Integrated Vulnerability Management & AI Usage Monitoring
Demonstrates core functionality with sample data and simplified integrations
"""

import json
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import hashlib
import re
import threading
import time
import logging
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityEvent:
    """Unified vulnerability event for both traditional and AI/MCP vulnerabilities"""
    event_id: str
    timestamp: str
    vulnerability_type: str
    severity: str
    source: str  # 'traditional', 'ai_usage', 'mcp'
    affected_asset: str
    user_context: Optional[str]
    risk_score: float
    description: str
    remediation_required: bool
    compliance_impact: List[str]
    status: str = 'open'

@dataclass
class AIUsageEvent:
    """AI usage monitoring event"""
    timestamp: str
    user_id: str
    ai_tool: str
    activity_type: str
    risk_level: str
    sensitive_data_detected: bool
    policy_violations: List[str]
    session_duration: int
    content_hash: str

@dataclass
class MCPEvent:
    """MCP protocol monitoring event"""
    timestamp: str
    session_id: str
    user_id: str
    server_name: str
    tool_name: str
    method: str
    success: bool
    risk_level: str
    vulnerability_patterns: List[str]

class IntegratedVulnerabilityDatabase:
    """Unified database for all vulnerability and monitoring data"""
    
    def __init__(self, db_path: str = "poc_integrated.db"):
        self.db_path = db_path
        self._init_database()
        self._populate_sample_data()
    
    def _init_database(self):
        """Initialize database with all required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Unified vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                affected_asset TEXT NOT NULL,
                user_context TEXT,
                risk_score REAL DEFAULT 0.0,
                description TEXT,
                remediation_required BOOLEAN DEFAULT TRUE,
                compliance_impact TEXT,
                status TEXT DEFAULT 'open',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # AI usage events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_usage_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT NOT NULL,
                ai_tool TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                sensitive_data_detected BOOLEAN DEFAULT FALSE,
                policy_violations TEXT,
                session_duration INTEGER DEFAULT 0,
                content_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # MCP events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mcp_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                session_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                server_name TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                method TEXT NOT NULL,
                success BOOLEAN DEFAULT TRUE,
                risk_level TEXT NOT NULL,
                vulnerability_patterns TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Monitoring alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_event_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'open',
                assigned_to TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    def _populate_sample_data(self):
        """Populate database with sample data for demonstration"""
        
        # Sample traditional vulnerabilities
        traditional_vulns = [
            VulnerabilityEvent(
                event_id="VULN-001",
                timestamp=datetime.utcnow().isoformat(),
                vulnerability_type="SQL Injection",
                severity="critical",
                source="traditional",
                affected_asset="web-server-01",
                user_context=None,
                risk_score=9.2,
                description="SQL injection vulnerability in login form",
                remediation_required=True,
                compliance_impact=["PCI-DSS", "SOX"]
            ),
            VulnerabilityEvent(
                event_id="VULN-002",
                timestamp=datetime.utcnow().isoformat(),
                vulnerability_type="Cross-Site Scripting",
                severity="high",
                source="traditional",
                affected_asset="web-app-dashboard",
                user_context=None,
                risk_score=7.8,
                description="Stored XSS in user comments section",
                remediation_required=True,
                compliance_impact=["GDPR"]
            )
        ]
        
        # Sample AI usage events
        ai_events = [
            AIUsageEvent(
                timestamp=datetime.utcnow().isoformat(),
                user_id="john.doe@company.com",
                ai_tool="ChatGPT",
                activity_type="document_generation",
                risk_level="medium",
                sensitive_data_detected=True,
                policy_violations=["external_ai_usage"],
                session_duration=45,
                content_hash="abc123def456"
            ),
            AIUsageEvent(
                timestamp=datetime.utcnow().isoformat(),
                user_id="jane.smith@company.com",
                ai_tool="GitHub Copilot",
                activity_type="code_generation",
                risk_level="low",
                sensitive_data_detected=False,
                policy_violations=[],
                session_duration=120,
                content_hash="def789ghi012"
            )
        ]
        
        # Sample MCP events
        mcp_events = [
            MCPEvent(
                timestamp=datetime.utcnow().isoformat(),
                session_id="mcp_session_001",
                user_id="developer@company.com",
                server_name="filesystem-server",
                tool_name="execute_command",
                method="tools/call",
                success=True,
                risk_level="high",
                vulnerability_patterns=["command_injection"]
            ),
            MCPEvent(
                timestamp=datetime.utcnow().isoformat(),
                session_id="mcp_session_002",
                user_id="analyst@company.com",
                server_name="database-server",
                tool_name="query_data",
                method="tools/call",
                success=True,
                risk_level="medium",
                vulnerability_patterns=[]
            )
        ]
        
        # Store sample data
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert traditional vulnerabilities
        for vuln in traditional_vulns:
            cursor.execute('''
                INSERT OR REPLACE INTO vulnerabilities 
                (event_id, timestamp, vulnerability_type, severity, source, affected_asset,
                 user_context, risk_score, description, remediation_required, compliance_impact)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln.event_id, vuln.timestamp, vuln.vulnerability_type, vuln.severity,
                vuln.source, vuln.affected_asset, vuln.user_context, vuln.risk_score,
                vuln.description, vuln.remediation_required, json.dumps(vuln.compliance_impact)
            ))
        
        # Insert AI usage events
        for event in ai_events:
            cursor.execute('''
                INSERT OR REPLACE INTO ai_usage_events 
                (timestamp, user_id, ai_tool, activity_type, risk_level, 
                 sensitive_data_detected, policy_violations, session_duration, content_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.timestamp, event.user_id, event.ai_tool, event.activity_type,
                event.risk_level, event.sensitive_data_detected, 
                json.dumps(event.policy_violations), event.session_duration, event.content_hash
            ))
        
        # Insert MCP events
        for event in mcp_events:
            cursor.execute('''
                INSERT OR REPLACE INTO mcp_events 
                (timestamp, session_id, user_id, server_name, tool_name, method,
                 success, risk_level, vulnerability_patterns)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.timestamp, event.session_id, event.user_id, event.server_name,
                event.tool_name, event.method, event.success, event.risk_level,
                json.dumps(event.vulnerability_patterns)
            ))
        
        conn.commit()
        conn.close()
        logger.info("Sample data populated successfully")

class VulnerabilityAnalyzer:
    """Analyzes and correlates vulnerabilities across all sources"""
    
    def __init__(self, db_path: str = "poc_integrated.db"):
        self.db_path = db_path
        self.vulnerability_patterns = {
            'command_injection': {
                'severity': 'critical',
                'description': 'Command injection vulnerability detected in MCP usage'
            },
            'credential_exposure': {
                'severity': 'high', 
                'description': 'Credential exposure detected in AI tool usage'
            },
            'sensitive_data_leak': {
                'severity': 'high',
                'description': 'Sensitive data exposure through AI tools'
            }
        }
    
    def analyze_ai_usage_for_vulnerabilities(self, ai_event: AIUsageEvent) -> Optional[VulnerabilityEvent]:
        """Analyze AI usage event for security vulnerabilities"""
        
        vulnerabilities = []
        
        # Check for sensitive data exposure
        if ai_event.sensitive_data_detected:
            vulnerabilities.append({
                'type': 'sensitive_data_leak',
                'severity': 'high',
                'description': f'Sensitive data detected in {ai_event.ai_tool} usage'
            })
        
        # Check for policy violations
        if ai_event.policy_violations:
            vulnerabilities.append({
                'type': 'policy_violation',
                'severity': 'medium',
                'description': f'Policy violations: {", ".join(ai_event.policy_violations)}'
            })
        
        # Check for high-risk usage patterns
        if ai_event.risk_level == 'high':
            vulnerabilities.append({
                'type': 'high_risk_usage',
                'severity': 'medium',
                'description': f'High-risk usage pattern detected for {ai_event.ai_tool}'
            })
        
        if not vulnerabilities:
            return None
        
        # Create vulnerability event for highest severity issue
        highest_vuln = max(vulnerabilities, key=lambda v: self._severity_to_score(v['severity']))
        
        return VulnerabilityEvent(
            event_id=f"AI-{hashlib.md5(ai_event.content_hash.encode()).hexdigest()[:8]}",
            timestamp=ai_event.timestamp,
            vulnerability_type=highest_vuln['type'],
            severity=highest_vuln['severity'],
            source='ai_usage',
            affected_asset=ai_event.ai_tool,
            user_context=ai_event.user_id,
            risk_score=self._calculate_ai_risk_score(ai_event),
            description=highest_vuln['description'],
            remediation_required=highest_vuln['severity'] in ['critical', 'high'],
            compliance_impact=self._get_compliance_impact(highest_vuln['type'])
        )
    
    def analyze_mcp_for_vulnerabilities(self, mcp_event: MCPEvent) -> Optional[VulnerabilityEvent]:
        """Analyze MCP event for security vulnerabilities"""
        
        if not mcp_event.vulnerability_patterns:
            return None
        
        # Analyze vulnerability patterns
        vulnerabilities = []
        for pattern in mcp_event.vulnerability_patterns:
            if pattern in self.vulnerability_patterns:
                pattern_info = self.vulnerability_patterns[pattern]
                vulnerabilities.append({
                    'type': pattern,
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description']
                })
        
        if not vulnerabilities:
            return None
        
        # Create vulnerability event for highest severity issue
        highest_vuln = max(vulnerabilities, key=lambda v: self._severity_to_score(v['severity']))
        
        return VulnerabilityEvent(
            event_id=f"MCP-{hashlib.md5(mcp_event.session_id.encode()).hexdigest()[:8]}",
            timestamp=mcp_event.timestamp,
            vulnerability_type=highest_vuln['type'],
            severity=highest_vuln['severity'],
            source='mcp',
            affected_asset=mcp_event.server_name,
            user_context=mcp_event.user_id,
            risk_score=self._calculate_mcp_risk_score(mcp_event),
            description=f"MCP {highest_vuln['description']} on {mcp_event.server_name}",
            remediation_required=highest_vuln['severity'] in ['critical', 'high'],
            compliance_impact=self._get_compliance_impact(highest_vuln['type'])
        )
    
    def _severity_to_score(self, severity: str) -> int:
        """Convert severity to numeric score"""
        scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        return scores.get(severity.lower(), 0)
    
    def _calculate_ai_risk_score(self, ai_event: AIUsageEvent) -> float:
        """Calculate risk score for AI usage event"""
        base_score = 5.0
        
        if ai_event.sensitive_data_detected:
            base_score += 3.0
        if ai_event.policy_violations:
            base_score += len(ai_event.policy_violations) * 1.0
        if ai_event.risk_level == 'high':
            base_score += 2.0
        
        return min(base_score, 10.0)
    
    def _calculate_mcp_risk_score(self, mcp_event: MCPEvent) -> float:
        """Calculate risk score for MCP event"""
        base_score = 6.0  # MCP events start higher due to protocol access
        
        if 'command_injection' in mcp_event.vulnerability_patterns:
            base_score += 4.0
        if 'credential_exposure' in mcp_event.vulnerability_patterns:
            base_score += 3.0
        if mcp_event.risk_level == 'high':
            base_score += 2.0
        
        return min(base_score, 10.0)
    
    def _get_compliance_impact(self, vulnerability_type: str) -> List[str]:
        """Get compliance frameworks impacted by vulnerability type"""
        compliance_mapping = {
            'sensitive_data_leak': ['GDPR', 'HIPAA'],
            'credential_exposure': ['SOX', 'PCI-DSS'],
            'command_injection': ['NIST', 'ISO27001'],
            'policy_violation': ['Internal Policy'],
            'high_risk_usage': ['Internal Policy']
        }
        return compliance_mapping.get(vulnerability_type, ['NIST'])

class RiskPrioritizationEngine:
    """Prioritizes vulnerabilities across all sources using unified scoring"""
    
    def __init__(self, db_path: str = "poc_integrated.db"):
        self.db_path = db_path
    
    def prioritize_vulnerabilities(self, limit: int = 10) -> List[Dict]:
        """Get top priority vulnerabilities across all sources"""
        
        conn = sqlite3.connect(self.db_path)
        
        # Get all open vulnerabilities with prioritization
        query = '''
            SELECT event_id, vulnerability_type, severity, source, affected_asset,
                   user_context, risk_score, description, compliance_impact,
                   timestamp
            FROM vulnerabilities 
            WHERE status = 'open'
            ORDER BY 
                CASE severity 
                    WHEN 'critical' THEN 4 
                    WHEN 'high' THEN 3 
                    WHEN 'medium' THEN 2 
                    WHEN 'low' THEN 1 
                END DESC,
                risk_score DESC,
                timestamp DESC
            LIMIT ?
        '''
        
        df = pd.read_sql_query(query, conn, params=(limit,))
        conn.close()
        
        if len(df) == 0:
            return []
        
        # Add prioritization context
        prioritized = []
        for _, row in df.iterrows():
            priority_context = self._calculate_priority_context(row)
            
            prioritized.append({
                'event_id': row['event_id'],
                'vulnerability_type': row['vulnerability_type'],
                'severity': row['severity'],
                'source': row['source'],
                'affected_asset': row['affected_asset'],
                'user_context': row['user_context'],
                'risk_score': row['risk_score'],
                'description': row['description'],
                'compliance_impact': json.loads(row['compliance_impact']) if row['compliance_impact'] else [],
                'priority_rank': priority_context['rank'],
                'business_impact': priority_context['business_impact'],
                'remediation_urgency': priority_context['urgency'],
                'timestamp': row['timestamp']
            })
        
        return prioritized
    
    def _calculate_priority_context(self, vulnerability_row) -> Dict:
        """Calculate additional priority context for vulnerability"""
        
        # Business impact assessment
        business_impact = 'medium'
        if vulnerability_row['severity'] == 'critical':
            business_impact = 'high'
        elif vulnerability_row['source'] == 'mcp' and vulnerability_row['severity'] == 'high':
            business_impact = 'high'  # MCP vulnerabilities get elevated priority
        
        # Urgency calculation
        urgency = 'medium'
        if vulnerability_row['risk_score'] >= 8.0:
            urgency = 'high'
        elif vulnerability_row['risk_score'] >= 6.0:
            urgency = 'medium'
        else:
            urgency = 'low'
        
        # Overall rank (1 = highest priority)
        rank = 1
        if vulnerability_row['severity'] == 'critical':
            rank = 1
        elif vulnerability_row['severity'] == 'high' and vulnerability_row['source'] in ['mcp', 'ai_usage']:
            rank = 2
        elif vulnerability_row['severity'] == 'high':
            rank = 3
        else:
            rank = 4
        
        return {
            'rank': rank,
            'business_impact': business_impact,
            'urgency': urgency
        }

class MonitoringOrchestrator:
    """Orchestrates monitoring and alerting across all systems"""
    
    def __init__(self, db_path: str = "poc_integrated.db"):
        self.db_path = db_path
        self.analyzer = VulnerabilityAnalyzer(db_path)
        self.prioritizer = RiskPrioritizationEngine(db_path)
        self.monitoring_active = False
    
    def start_monitoring(self):
        """Start continuous monitoring of all event sources"""
        self.monitoring_active = True
        
        # Start monitoring thread
        monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        monitoring_thread.start()
        
        logger.info("Monitoring orchestrator started")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring_active = False
        logger.info("Monitoring orchestrator stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Process new AI usage events
                self._process_new_ai_events()
                
                # Process new MCP events
                self._process_new_mcp_events()
                
                # Generate alerts for high-priority vulnerabilities
                self._generate_priority_alerts()
                
                # Sleep for monitoring interval
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {e}")
                time.sleep(60)  # Wait longer on error
    
    def _process_new_ai_events(self):
        """Process new AI usage events for vulnerabilities"""
        conn = sqlite3.connect(self.db_path)
        
        # Get recent AI events that haven't been processed
        recent_events = pd.read_sql_query('''
            SELECT * FROM ai_usage_events 
            WHERE created_at > datetime('now', '-1 hour')
        ''', conn)
        
        conn.close()
        
        for _, row in recent_events.iterrows():
            ai_event = AIUsageEvent(
                timestamp=row['timestamp'],
                user_id=row['user_id'],
                ai_tool=row['ai_tool'],
                activity_type=row['activity_type'],
                risk_level=row['risk_level'],
                sensitive_data_detected=row['sensitive_data_detected'],
                policy_violations=json.loads(row['policy_violations']),
                session_duration=row['session_duration'],
                content_hash=row['content_hash']
            )
            
            # Analyze for vulnerabilities
            vulnerability = self.analyzer.analyze_ai_usage_for_vulnerabilities(ai_event)
            
            if vulnerability:
                self._store_vulnerability(vulnerability)
                logger.info(f"AI vulnerability detected: {vulnerability.event_id}")
    
    def _process_new_mcp_events(self):
        """Process new MCP events for vulnerabilities"""
        conn = sqlite3.connect(self.db_path)
        
        # Get recent MCP events
        recent_events = pd.read_sql_query('''
            SELECT * FROM mcp_events 
            WHERE created_at > datetime('now', '-1 hour')
        ''', conn)
        
        conn.close()
        
        for _, row in recent_events.iterrows():
            mcp_event = MCPEvent(
                timestamp=row['timestamp'],
                session_id=row['session_id'],
                user_id=row['user_id'],
                server_name=row['server_name'],
                tool_name=row['tool_name'],
                method=row['method'],
                success=row['success'],
                risk_level=row['risk_level'],
                vulnerability_patterns=json.loads(row['vulnerability_patterns'])
            )
            
            # Analyze for vulnerabilities
            vulnerability = self.analyzer.analyze_mcp_for_vulnerabilities(mcp_event)
            
            if vulnerability:
                self._store_vulnerability(vulnerability)
                logger.info(f"MCP vulnerability detected: {vulnerability.event_id}")
    
    def _store_vulnerability(self, vulnerability: VulnerabilityEvent):
        """Store vulnerability in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO vulnerabilities 
            (event_id, timestamp, vulnerability_type, severity, source, affected_asset,
             user_context, risk_score, description, remediation_required, compliance_impact)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            vulnerability.event_id, vulnerability.timestamp, vulnerability.vulnerability_type,
            vulnerability.severity, vulnerability.source, vulnerability.affected_asset,
            vulnerability.user_context, vulnerability.risk_score, vulnerability.description,
            vulnerability.remediation_required, json.dumps(vulnerability.compliance_impact)
        ))
        
        conn.commit()
        conn.close()
    
    def _generate_priority_alerts(self):
        """Generate alerts for high-priority vulnerabilities"""
        
        # Get top priority vulnerabilities
        top_vulns = self.prioritizer.prioritize_vulnerabilities(limit=5)
        
        for vuln in top_vulns:
            if vuln['severity'] in ['critical', 'high'] and vuln['priority_rank'] <= 2:
                self._create_alert(vuln)
    
    def _create_alert(self, vulnerability: Dict):
        """Create monitoring alert"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if alert already exists
        cursor.execute('''
            SELECT id FROM monitoring_alerts 
            WHERE source_event_id = ? AND status = 'open'
        ''', (vulnerability['event_id'],))
        
        if cursor.fetchone():
            conn.close()
            return  # Alert already exists
        
        # Create new alert
        cursor.execute('''
            INSERT INTO monitoring_alerts 
            (alert_type, severity, source_event_id, title, description, assigned_to)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            f"{vulnerability['source']}_vulnerability",
            vulnerability['severity'],
            vulnerability['event_id'],
            f"{vulnerability['severity'].title()} {vulnerability['vulnerability_type']} - {vulnerability['affected_asset']}",
            vulnerability['description'],
            'security-team'
        ))
        
        conn.commit()
        conn.close()
        
        logger.warning(f"Alert created for {vulnerability['event_id']}: {vulnerability['vulnerability_type']}")

class POCWebInterface:
    """Simple web interface for the proof of concept"""
    
    def __init__(self, db_path: str = "poc_integrated.db"):
        self.db_path = db_path
        self.app = Flask(__name__)
        self.prioritizer = RiskPrioritizationEngine(db_path)
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            return '''
            <html>
            <head><title>Integrated VM & AI Monitoring POC</title></head>
            <body>
                <h1>Integrated Vulnerability Management & AI Monitoring POC</h1>
                <h2>Available Endpoints:</h2>
                <ul>
                    <li><a href="/vulnerabilities">Top Priority Vulnerabilities</a></li>
                    <li><a href="/ai-usage">AI Usage Events</a></li>
                    <li><a href="/mcp-events">MCP Events</a></li>
                    <li><a href="/alerts">Active Alerts</a></li>
                    <li><a href="/dashboard">Executive Dashboard</a></li>
                    <li><a href="/simulate-event">Simulate New Event</a></li>
                </ul>
            </body>
            </html>
            '''
        
        @self.app.route('/vulnerabilities')
        def get_vulnerabilities():
            vulnerabilities = self.prioritizer.prioritize_vulnerabilities(limit=20)
            return jsonify({
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerabilities': vulnerabilities
            })
        
        @self.app.route('/ai-usage')
        def get_ai_usage():
            conn = sqlite3.connect(self.db_path)
            df = pd.read_sql_query('SELECT * FROM ai_usage_events ORDER BY created_at DESC LIMIT 20', conn)
            conn.close()
            
            return jsonify({
                'total_events': len(df),
                'events': df.to_dict('records')
            })
        
        @self.app.route('/mcp-events')
        def get_mcp_events():
            conn = sqlite3.connect(self.db_path)
            df = pd.read_sql_query('SELECT * FROM mcp_events ORDER BY created_at DESC LIMIT 20', conn)
            conn.close()
            
            return jsonify({
                'total_events': len(df),
                'events': df.to_dict('records')
            })
        
        @self.app.route('/alerts')
        def get_alerts():
            conn = sqlite3.connect(self.db_path)
            df = pd.read_sql_query('SELECT * FROM monitoring_alerts WHERE status = "open" ORDER BY created_at DESC', conn)
            conn.close()
            
            return jsonify({
                'active_alerts': len(df),
                'alerts': df.to_dict('records')
            })
        
        @self.app.route('/dashboard')
        def executive_dashboard():
            conn = sqlite3.connect(self.db_path)
            
            # Get summary statistics
            vuln_stats = pd.read_sql_query('''
                SELECT source, severity, COUNT(*) as count
                FROM vulnerabilities 
                WHERE status = 'open'
                GROUP BY source, severity
            ''', conn)
            
            ai_stats = pd.read_sql_query('''
                SELECT risk_level, COUNT(*) as count
                FROM ai_usage_events
                WHERE created_at > datetime('now', '-7 days')
                GROUP BY risk_level
            ''', conn)
            
            mcp_stats = pd.read_sql_query('''
                SELECT risk_level, COUNT(*) as count
                FROM mcp_events
                WHERE created_at > datetime('now', '-7 days')
                GROUP BY risk_level
            ''', conn)
            
            conn.close()
            
            return jsonify({
                'vulnerability_summary': vuln_stats.to_dict('records'),
                'ai_usage_summary': ai_stats.to_dict('records'),
                'mcp_usage_summary': mcp_stats.to_dict('records'),
                'generated_at': datetime.utcnow().isoformat()
            })
        
        @self.app.route('/simulate-event', methods=['GET', 'POST'])
        def simulate_event():
            if request.method == 'GET':
                return '''
                <html>
                <body>
                    <h2>Simulate New Event</h2>
                    <form method="POST">
                        <h3>Event Type:</h3>
                        <input type="radio" name="event_type" value="ai" checked> AI Usage Event<br>
                        <input type="radio" name="event_type" value="mcp"> MCP Event<br><br>
                        
                        <h3>Risk Level:</h3>
                        <select name="risk_level">
                            <option value="low">Low</option>
                            <option value="medium">Medium</option>
                            <option value="high">High</option>
                        </select><br><br>
                        
                        <h3>Include Vulnerability Pattern:</h3>
                        <input type="checkbox" name="include_vulnerability" value="true"> Yes<br><br>
                        
                        <input type="submit" value="Simulate Event">
                    </form>
                </body>
                </html>
                '''
            
            # Process simulation
            event_type = request.form.get('event_type')
            risk_level = request.form.get('risk_level', 'medium')
            include_vuln = request.form.get('include_vulnerability') == 'true'
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if event_type == 'ai':
                # Simulate AI usage event
                cursor.execute('''
                    INSERT INTO ai_usage_events 
                    (timestamp, user_id, ai_tool, activity_type, risk_level, 
                     sensitive_data_detected, policy_violations, session_duration, content_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.utcnow().isoformat(),
                    'simulated.user@company.com',
                    'ChatGPT',
                    'document_analysis',
                    risk_level,
                    include_vuln,
                    json.dumps(['external_ai_usage'] if include_vuln else []),
                    60,
                    f"sim_{int(time.time())}"
                ))
            
            elif event_type == 'mcp':
                # Simulate MCP event
                vulnerability_patterns = ['command_injection'] if include_vuln else []
                
                cursor.execute('''
                    INSERT INTO mcp_events 
                    (timestamp, session_id, user_id, server_name, tool_name, method,
                     success, risk_level, vulnerability_patterns)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.utcnow().isoformat(),
                    f"sim_session_{int(time.time())}",
                    'simulated.user@company.com',
                    'filesystem-server',
                    'execute_command',
                    'tools/call',
                    True,
                    risk_level,
                    json.dumps(vulnerability_patterns)
                ))
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'status': 'success',
                'message': f'Simulated {event_type} event with {risk_level} risk level',
                'include_vulnerability': include_vuln
            })
    
    def run(self, host='localhost', port=5000, debug=True):
        """Run the web interface"""
        self.app.run(host=host, port=port, debug=debug)

def main():
    """Main function to run the 30-minute POC"""
    
    print("🚀 Starting 30-Minute Integrated VM & AI Monitoring POC")
    print("=" * 60)
    
    # Initialize database
    print("📊 Initializing integrated database...")
    db = IntegratedVulnerabilityDatabase()
    
    # Start monitoring
    print("🔍 Starting monitoring orchestrator...")
    orchestrator = MonitoringOrchestrator()
    orchestrator.start_monitoring()
    
    # Initialize web interface
    print("🌐 Starting web interface...")
    web_interface = POCWebInterface()
    
    print("\n✅ POC System Ready!")
    print("=" * 60)
    print("📋 System Components:")
    print("   • Integrated vulnerability database with sample data")
    print("   • AI usage monitoring and analysis")
    print("   • MCP protocol monitoring and vulnerability detection")
    print("   • Unified risk prioritization engine")
    print("   • Real-time monitoring and alerting")
    print("   • Web interface for demonstration")
    
    print("\n🌐 Web Interface Available:")
    print("   • Dashboard: http://localhost:5000")
    print("   • Vulnerabilities: http://localhost:5000/vulnerabilities")
    print("   • AI Usage: http://localhost:5000/ai-usage")
    print("   • MCP Events: http://localhost:5000/mcp-events")
    print("   • Alerts: http://localhost:5000/alerts")
    print("   • Executive Dashboard: http://localhost:5000/dashboard")
    print("   • Event Simulator: http://localhost:5000/simulate-event")
    
    print("\n🎯 Demo Scenarios:")
    print("   1. View prioritized vulnerabilities across all sources")
    print("   2. Monitor AI usage events and policy violations")
    print("   3. Track MCP protocol vulnerabilities")
    print("   4. Simulate new events and see real-time processing")
    print("   5. View executive dashboard with integrated metrics")
    
    print("\n🔧 Next Steps for Full Implementation:")
    print("   • Deploy to AWS with Bedrock AgentCore")
    print("   • Integrate with Sumo Logic, Rapid7, and Jira")
    print("   • Add real MCP protocol monitoring")
    print("   • Implement automated remediation workflows")
    print("   • Scale monitoring infrastructure")
    
    try:
        # Run web interface
        web_interface.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n🛑 Stopping POC system...")
        orchestrator.stop_monitoring()
        print("✅ POC system stopped successfully")

if __name__ == "__main__":
    main()