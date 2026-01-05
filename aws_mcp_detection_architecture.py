"""
AWS-Based Unauthorized MCP Detection Architecture
Comprehensive solution using AWS services for detecting unauthorized third-party MCP usage
"""

import json
import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AWSMCPDetectionArchitecture:
    """
    AWS-based architecture for detecting unauthorized MCP usage
    
    Key AWS Services Used:
    1. VPC Flow Logs - Network traffic analysis
    2. GuardDuty - Threat detection
    3. CloudTrail - API activity monitoring
    4. Config - Configuration compliance
    5. Inspector - Vulnerability assessment
    6. Security Hub - Centralized security findings
    7. EventBridge - Event routing
    8. Lambda - Serverless processing
    9. Kinesis - Real-time data streaming
    10. OpenSearch - Log analysis and search
    11. SNS/SQS - Alerting and messaging
    12. Systems Manager - Endpoint monitoring
    13. WAF - Web application firewall
    14. Network Firewall - Advanced network protection
    """
    
    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.session = boto3.Session(region_name=region)
        
        # Initialize AWS service clients
        self.ec2 = self.session.client('ec2')
        self.guardduty = self.session.client('guardduty')
        self.cloudtrail = self.session.client('cloudtrail')
        self.config = self.session.client('config')
        self.inspector = self.session.client('inspector2')
        self.security_hub = self.session.client('securityhub')
        self.events = self.session.client('events')
        self.lambda_client = self.session.client('lambda')
        self.kinesis = self.session.client('kinesis')
        self.opensearch = self.session.client('opensearch')
        self.sns = self.session.client('sns')
        self.ssm = self.session.client('ssm')
        self.waf = self.session.client('wafv2')
        self.network_firewall = self.session.client('network-firewall')

# AWS Service Components for MCP Detection

class VPCFlowLogsAnalyzer:
    """
    Use VPC Flow Logs to detect MCP traffic patterns
    
    VPC Flow Logs capture:
    - Source/destination IPs and ports
    - Protocol information
    - Packet and byte counts
    - Accept/reject decisions
    """
    
    def __init__(self, session: boto3.Session):
        self.ec2 = session.client('ec2')
        self.s3 = session.client('s3')
        self.athena = session.client('athena')
    
    def setup_flow_logs_for_mcp_detection(self, vpc_id: str, s3_bucket: str) -> Dict:
        """Setup VPC Flow Logs with MCP-specific configuration"""
        
        # Create flow log with custom format for MCP detection
        flow_log_format = (
            "${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} "
            "${packets} ${bytes} ${windowstart} ${windowend} ${action} "
            "${flowlogstatus} ${instance-id} ${interface-id} ${account-id} "
            "${vpc-id} ${subnet-id} ${region} ${az-id} ${sublocation-type} "
            "${sublocation-id} ${pkt-src-aws-service} ${pkt-dst-aws-service}"
        )
        
        try:
            response = self.ec2.create_flow_logs(
                ResourceIds=[vpc_id],
                ResourceType='VPC',
                TrafficType='ALL',
                LogDestinationType='s3',
                LogDestination=f'arn:aws:s3:::{s3_bucket}/vpc-flow-logs/',
                LogFormat=flow_log_format,
                TagSpecifications=[
                    {
                        'ResourceType': 'vpc-flow-log',
                        'Tags': [
                            {'Key': 'Purpose', 'Value': 'MCP-Detection'},
                            {'Key': 'Component', 'Value': 'UnauthorizedMCPMonitoring'}
                        ]
                    }
                ]
            )
            
            return {
                'flow_log_ids': response['FlowLogIds'],
                'status': 'created',
                'destination': f's3://{s3_bucket}/vpc-flow-logs/'
            }
            
        except Exception as e:
            logger.error(f"Failed to create VPC Flow Logs: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def create_athena_queries_for_mcp_detection(self, database: str, table: str) -> List[str]:
        """Create Athena queries to detect MCP traffic patterns"""
        
        queries = [
            # Query 1: Detect connections to common MCP ports
            f"""
            SELECT 
                srcaddr, dstaddr, dstport, 
                COUNT(*) as connection_count,
                SUM(bytes) as total_bytes,
                MIN(windowstart) as first_seen,
                MAX(windowend) as last_seen
            FROM {database}.{table}
            WHERE dstport IN (8080, 3000, 5000, 8000, 9000, 8443)
                AND action = 'ACCEPT'
                AND windowstart >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
            GROUP BY srcaddr, dstaddr, dstport
            HAVING connection_count > 10
            ORDER BY total_bytes DESC
            """,
            
            # Query 2: Detect WebSocket upgrade patterns (HTTP -> WebSocket)
            f"""
            SELECT 
                srcaddr, dstaddr,
                COUNT(DISTINCT dstport) as unique_ports,
                SUM(bytes) as total_bytes
            FROM {database}.{table}
            WHERE (dstport = 80 OR dstport = 443 OR dstport = 8080)
                AND action = 'ACCEPT'
                AND windowstart >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
            GROUP BY srcaddr, dstaddr
            HAVING total_bytes > 1000000  -- Large data transfers
            ORDER BY total_bytes DESC
            """,
            
            # Query 3: Detect connections to suspicious geographic regions
            f"""
            SELECT 
                srcaddr, dstaddr, dstport,
                COUNT(*) as connection_count,
                SUM(bytes) as total_bytes
            FROM {database}.{table}
            WHERE action = 'ACCEPT'
                AND windowstart >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
                -- Add IP ranges for high-risk countries
                AND (
                    dstaddr LIKE '185.220.%'  -- Example: Tor exit nodes
                    OR dstaddr LIKE '103.%'   -- Example: Suspicious ranges
                )
            GROUP BY srcaddr, dstaddr, dstport
            ORDER BY connection_count DESC
            """
        ]
        
        return queries

class GuardDutyMCPDetector:
    """
    Extend GuardDuty with custom MCP threat detection
    
    GuardDuty can detect:
    - Malicious IP communications
    - DNS data exfiltration
    - Cryptocurrency mining
    - Suspicious network activity
    """
    
    def __init__(self, session: boto3.Session):
        self.guardduty = session.client('guardduty')
        self.s3 = session.client('s3')
    
    def setup_custom_threat_intelligence(self, detector_id: str, s3_bucket: str) -> Dict:
        """Setup custom threat intelligence for MCP-related threats"""
        
        # Create threat intelligence set for known malicious MCP servers
        threat_intel_config = {
            'name': 'UnauthorizedMCPServers',
            'format': 'TXT',
            'location': f'https://{s3_bucket}.s3.amazonaws.com/threat-intel/mcp-malicious-ips.txt',
            'activate': True,
            'tags': {
                'Purpose': 'MCP-Detection',
                'ThreatType': 'UnauthorizedMCPServers'
            }
        }
        
        try:
            response = self.guardduty.create_threat_intel_set(
                DetectorId=detector_id,
                **threat_intel_config
            )
            
            return {
                'threat_intel_set_id': response['ThreatIntelSetId'],
                'status': 'created'
            }
            
        except Exception as e:
            logger.error(f"Failed to create threat intelligence set: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def create_custom_mcp_findings(self, detector_id: str) -> List[Dict]:
        """Create custom findings for MCP-related threats"""
        
        custom_findings = [
            {
                'type': 'UnauthorizedMCP/Communication',
                'title': 'Unauthorized MCP Server Communication Detected',
                'description': 'Instance communicating with unauthorized MCP server',
                'severity': 8.0,
                'confidence': 7.0
            },
            {
                'type': 'UnauthorizedMCP/DataExfiltration',
                'title': 'Potential Data Exfiltration via MCP',
                'description': 'Large data transfer to unauthorized MCP server detected',
                'severity': 9.0,
                'confidence': 8.0
            },
            {
                'type': 'UnauthorizedMCP/SuspiciousDomain',
                'title': 'Connection to Suspicious MCP Domain',
                'description': 'Connection to domain with suspicious MCP characteristics',
                'severity': 6.0,
                'confidence': 6.0
            }
        ]
        
        return custom_findings

class CloudTrailMCPMonitor:
    """
    Use CloudTrail to monitor API activities related to MCP usage
    
    CloudTrail can track:
    - EC2 instance launches with MCP software
    - IAM role assumptions for MCP access
    - S3 access to MCP-related data
    - Lambda function executions
    """
    
    def __init__(self, session: boto3.Session):
        self.cloudtrail = session.client('cloudtrail')
        self.logs = session.client('logs')
    
    def setup_mcp_specific_trail(self, trail_name: str, s3_bucket: str) -> Dict:
        """Setup CloudTrail with MCP-specific event filtering"""
        
        try:
            # Create trail with advanced event selectors
            response = self.cloudtrail.create_trail(
                Name=trail_name,
                S3BucketName=s3_bucket,
                S3KeyPrefix='mcp-cloudtrail-logs/',
                IncludeGlobalServiceEvents=True,
                IsMultiRegionTrail=True,
                EnableLogFileValidation=True,
                EventSelectors=[
                    {
                        'ReadWriteType': 'All',
                        'IncludeManagementEvents': True,
                        'DataResources': [
                            {
                                'Type': 'AWS::S3::Object',
                                'Values': ['arn:aws:s3:::*mcp*/*']  # MCP-related S3 objects
                            },
                            {
                                'Type': 'AWS::Lambda::Function',
                                'Values': ['arn:aws:lambda:*:*:function:*mcp*']  # MCP Lambda functions
                            }
                        ]
                    }
                ],
                Tags=[
                    {'Key': 'Purpose', 'Value': 'MCP-Detection'},
                    {'Key': 'Component', 'Value': 'APIMonitoring'}
                ]
            )
            
            return {
                'trail_arn': response['TrailARN'],
                'status': 'created'
            }
            
        except Exception as e:
            logger.error(f"Failed to create CloudTrail: {e}")
            return {'status': 'failed', 'error': str(e)}
    
    def create_cloudwatch_insights_queries(self) -> List[str]:
        """Create CloudWatch Insights queries for MCP activity detection"""
        
        queries = [
            # Query 1: Detect EC2 instances launched with MCP-related user data
            """
            fields @timestamp, sourceIPAddress, userIdentity.type, requestParameters.userData
            | filter eventName = "RunInstances"
            | filter requestParameters.userData like /mcp|claude|anthropic/
            | sort @timestamp desc
            """,
            
            # Query 2: Monitor IAM role assumptions for MCP access
            """
            fields @timestamp, sourceIPAddress, userIdentity, requestParameters.roleArn
            | filter eventName = "AssumeRole"
            | filter requestParameters.roleArn like /mcp|ai|anthropic/
            | stats count() by userIdentity.principalId
            | sort count desc
            """,
            
            # Query 3: Track S3 access to MCP-related objects
            """
            fields @timestamp, sourceIPAddress, requestParameters.bucketName, requestParameters.key
            | filter eventSource = "s3.amazonaws.com"
            | filter requestParameters.key like /mcp|model|ai/
            | filter eventName in ["GetObject", "PutObject", "DeleteObject"]
            | sort @timestamp desc
            """
        ]
        
        return queries

class ConfigMCPCompliance:
    """
    Use AWS Config to ensure MCP usage compliance
    
    Config can monitor:
    - Security group configurations
    - IAM policy compliance
    - Resource tagging compliance
    - Network ACL configurations
    """
    
    def __init__(self, session: boto3.Session):
        self.config = session.client('config')
    
    def create_mcp_compliance_rules(self) -> List[Dict]:
        """Create Config rules for MCP compliance monitoring"""
        
        compliance_rules = [
            {
                'ConfigRuleName': 'mcp-security-group-compliance',
                'Description': 'Ensures security groups do not allow unrestricted access to MCP ports',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'INCOMING_SSH_DISABLED'  # Base rule, customize for MCP ports
                },
                'InputParameters': json.dumps({
                    'blockedPorts': '8080,3000,5000,8000,9000'
                })
            },
            {
                'ConfigRuleName': 'mcp-instance-tagging-compliance',
                'Description': 'Ensures EC2 instances with MCP software are properly tagged',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'REQUIRED_TAGS'
                },
                'InputParameters': json.dumps({
                    'tag1Key': 'MCPUsage',
                    'tag1Value': 'Authorized,Unauthorized'
                })
            },
            {
                'ConfigRuleName': 'mcp-iam-policy-compliance',
                'Description': 'Ensures IAM policies for MCP access follow least privilege',
                'Source': {
                    'Owner': 'AWS',
                    'SourceIdentifier': 'IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS'
                }
            }
        ]
        
        return compliance_rules

class SystemsManagerMCPAgent:
    """
    Use Systems Manager for endpoint-level MCP monitoring
    
    Systems Manager can:
    - Install monitoring agents on EC2 instances
    - Collect process and network information
    - Execute remediation scripts
    - Manage compliance baselines
    """
    
    def __init__(self, session: boto3.Session):
        self.ssm = session.client('ssm')
    
    def create_mcp_monitoring_document(self) -> Dict:
        """Create SSM document for MCP process monitoring"""
        
        document_content = {
            "schemaVersion": "2.2",
            "description": "Monitor and detect unauthorized MCP processes",
            "parameters": {
                "action": {
                    "type": "String",
                    "description": "Action to perform: monitor, block, or report",
                    "default": "monitor",
                    "allowedValues": ["monitor", "block", "report"]
                }
            },
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "detectMCPProcesses",
                    "inputs": {
                        "runCommand": [
                            "#!/bin/bash",
                            "# Detect MCP-related processes",
                            "ps aux | grep -E '(mcp|claude|anthropic|uvx.*mcp)' | grep -v grep > /tmp/mcp_processes.txt",
                            "",
                            "# Check network connections",
                            "netstat -tulpn | grep -E ':(8080|3000|5000|8000|9000)' > /tmp/mcp_connections.txt",
                            "",
                            "# Analyze DNS queries",
                            "tail -n 1000 /var/log/syslog | grep -E '(mcp|anthropic|claude)' > /tmp/mcp_dns.txt",
                            "",
                            "# Create report",
                            "echo '{' > /tmp/mcp_report.json",
                            "echo '\"timestamp\": \"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'\",' >> /tmp/mcp_report.json",
                            "echo '\"hostname\": \"'$(hostname)'\",' >> /tmp/mcp_report.json",
                            "echo '\"processes\": [' >> /tmp/mcp_report.json",
                            "cat /tmp/mcp_processes.txt | while read line; do",
                            "  echo '\"'$line'\",' >> /tmp/mcp_report.json",
                            "done",
                            "echo '],' >> /tmp/mcp_report.json",
                            "echo '\"connections\": [' >> /tmp/mcp_report.json",
                            "cat /tmp/mcp_connections.txt | while read line; do",
                            "  echo '\"'$line'\",' >> /tmp/mcp_report.json",
                            "done",
                            "echo ']' >> /tmp/mcp_report.json",
                            "echo '}' >> /tmp/mcp_report.json",
                            "",
                            "# Send to CloudWatch Logs",
                            "aws logs put-log-events --log-group-name '/aws/ssm/mcp-monitoring' --log-stream-name $(hostname) --log-events timestamp=$(date +%s000),message=\"$(cat /tmp/mcp_report.json)\""
                        ]
                    }
                }
            ]
        }
        
        try:
            response = self.ssm.create_document(
                Content=json.dumps(document_content),
                Name='MCP-Process-Monitor',
                DocumentType='Command',
                DocumentFormat='JSON',
                Tags=[
                    {'Key': 'Purpose', 'Value': 'MCP-Detection'},
                    {'Key': 'Component', 'Value': 'EndpointMonitoring'}
                ]
            )
            
            return {
                'document_name': response['DocumentDescription']['Name'],
                'status': 'created'
            }
            
        except Exception as e:
            logger.error(f"Failed to create SSM document: {e}")
            return {'status': 'failed', 'error': str(e)}

class LambdaMCPProcessor:
    """
    Lambda functions for real-time MCP event processing
    
    Lambda functions can:
    - Process VPC Flow Logs in real-time
    - Analyze CloudTrail events
    - Execute automated responses
    - Integrate with external systems
    """
    
    def __init__(self, session: boto3.Session):
        self.lambda_client = session.client('lambda')
        self.iam = session.client('iam')
    
    def create_mcp_detection_lambda(self) -> Dict:
        """Create Lambda function for MCP detection processing"""
        
        lambda_code = '''
import json
import boto3
import re
from datetime import datetime

def lambda_handler(event, context):
    """
    Process VPC Flow Logs and CloudTrail events for MCP detection
    """
    
    # Initialize AWS clients
    sns = boto3.client('sns')
    security_hub = boto3.client('securityhub')
    
    findings = []
    
    # Process different event types
    if 'Records' in event:
        for record in event['Records']:
            if record.get('eventSource') == 'aws:s3':
                # Process VPC Flow Logs from S3
                findings.extend(process_flow_logs(record))
            elif record.get('eventSource') == 'aws:cloudtrail':
                # Process CloudTrail events
                findings.extend(process_cloudtrail_events(record))
    
    # Send findings to Security Hub
    if findings:
        security_hub.batch_import_findings(Findings=findings)
        
        # Send high-severity alerts to SNS
        high_severity_findings = [f for f in findings if f.get('Severity', {}).get('Normalized', 0) >= 70]
        if high_severity_findings:
            sns.publish(
                TopicArn=os.environ['SNS_TOPIC_ARN'],
                Subject='High Severity MCP Security Alert',
                Message=json.dumps(high_severity_findings, indent=2)
            )
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'processed_events': len(event.get('Records', [])),
            'findings_created': len(findings)
        })
    }

def process_flow_logs(record):
    """Process VPC Flow Logs for MCP traffic patterns"""
    findings = []
    
    # MCP-related ports
    mcp_ports = [8080, 3000, 5000, 8000, 9000, 8443]
    
    # Analyze flow log data
    # (Implementation would parse actual flow log data)
    
    return findings

def process_cloudtrail_events(record):
    """Process CloudTrail events for MCP-related activities"""
    findings = []
    
    # Look for MCP-related API calls
    # (Implementation would analyze CloudTrail event data)
    
    return findings
        '''
        
        # Create IAM role for Lambda
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        try:
            # Create IAM role
            role_response = self.iam.create_role(
                RoleName='MCPDetectionLambdaRole',
                AssumeRolePolicyDocument=json.dumps(assume_role_policy),
                Description='IAM role for MCP detection Lambda function'
            )
            
            # Attach policies
            self.iam.attach_role_policy(
                RoleName='MCPDetectionLambdaRole',
                PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
            )
            
            # Create Lambda function
            lambda_response = self.lambda_client.create_function(
                FunctionName='mcp-detection-processor',
                Runtime='python3.9',
                Role=role_response['Role']['Arn'],
                Handler='lambda_function.lambda_handler',
                Code={'ZipFile': lambda_code.encode()},
                Description='Process events for unauthorized MCP usage detection',
                Timeout=300,
                Environment={
                    'Variables': {
                        'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:mcp-security-alerts'
                    }
                },
                Tags={
                    'Purpose': 'MCP-Detection',
                    'Component': 'EventProcessing'
                }
            )
            
            return {
                'function_arn': lambda_response['FunctionArn'],
                'role_arn': role_response['Role']['Arn'],
                'status': 'created'
            }
            
        except Exception as e:
            logger.error(f"Failed to create Lambda function: {e}")
            return {'status': 'failed', 'error': str(e)}

class NetworkFirewallMCPProtection:
    """
    Use AWS Network Firewall for advanced MCP traffic filtering
    
    Network Firewall can:
    - Inspect traffic at Layer 3-7
    - Block based on domain names
    - Apply custom rules for MCP protocols
    - Log all network activity
    """
    
    def __init__(self, session: boto3.Session):
        self.network_firewall = session.client('network-firewall')
    
    def create_mcp_firewall_rules(self) -> Dict:
        """Create Network Firewall rules for MCP traffic control"""
        
        # Suricata rules for MCP detection
        suricata_rules = [
            # Detect MCP JSON-RPC traffic
            'alert tcp any any -> any any (msg:"Unauthorized MCP JSON-RPC Traffic"; content:"jsonrpc"; content:"2.0"; content:"method"; content:"tools/call"; sid:1000001; rev:1;)',
            
            # Detect MCP initialization
            'alert tcp any any -> any any (msg:"MCP Protocol Initialization"; content:"initialize"; content:"protocolVersion"; sid:1000002; rev:1;)',
            
            # Detect connections to suspicious MCP domains
            'alert dns any any -> any any (msg:"Suspicious MCP Domain Query"; dns.query; content:"mcp"; nocase; sid:1000003; rev:1;)',
            
            # Detect large data transfers to unauthorized servers
            'alert tcp any any -> any [8080,3000,5000,8000,9000] (msg:"Large Data Transfer to MCP Port"; threshold:type both, track by_src, count 100, seconds 60; sid:1000004; rev:1;)'
        ]
        
        rule_group = {
            'RuleGroupName': 'MCP-Detection-Rules',
            'Type': 'STATEFUL',
            'Description': 'Rules for detecting unauthorized MCP usage',
            'Capacity': 100,
            'RuleGroup': {
                'RulesSource': {
                    'RulesString': '\n'.join(suricata_rules)
                },
                'StatefulRuleOptions': {
                    'RuleOrder': 'STRICT_ORDER'
                }
            },
            'Tags': [
                {'Key': 'Purpose', 'Value': 'MCP-Detection'},
                {'Key': 'Component', 'Value': 'NetworkFiltering'}
            ]
        }
        
        return rule_group

# Complete AWS Architecture Implementation
class AWSMCPDetectionOrchestrator:
    """
    Orchestrates all AWS components for comprehensive MCP detection
    """
    
    def __init__(self, region: str = 'us-east-1'):
        self.region = region
        self.session = boto3.Session(region_name=region)
        
        # Initialize component classes
        self.vpc_analyzer = VPCFlowLogsAnalyzer(self.session)
        self.guardduty_detector = GuardDutyMCPDetector(self.session)
        self.cloudtrail_monitor = CloudTrailMCPMonitor(self.session)
        self.config_compliance = ConfigMCPCompliance(self.session)
        self.ssm_agent = SystemsManagerMCPAgent(self.session)
        self.lambda_processor = LambdaMCPProcessor(self.session)
        self.network_firewall = NetworkFirewallMCPProtection(self.session)
    
    def deploy_complete_architecture(self, config: Dict) -> Dict:
        """Deploy complete AWS architecture for MCP detection"""
        
        deployment_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'region': self.region,
            'components': {}
        }
        
        try:
            # 1. Setup VPC Flow Logs
            logger.info("Setting up VPC Flow Logs...")
            flow_logs_result = self.vpc_analyzer.setup_flow_logs_for_mcp_detection(
                config['vpc_id'], 
                config['s3_bucket']
            )
            deployment_results['components']['vpc_flow_logs'] = flow_logs_result
            
            # 2. Configure GuardDuty
            logger.info("Configuring GuardDuty...")
            guardduty_result = self.guardduty_detector.setup_custom_threat_intelligence(
                config['guardduty_detector_id'],
                config['s3_bucket']
            )
            deployment_results['components']['guardduty'] = guardduty_result
            
            # 3. Setup CloudTrail
            logger.info("Setting up CloudTrail...")
            cloudtrail_result = self.cloudtrail_monitor.setup_mcp_specific_trail(
                'mcp-detection-trail',
                config['s3_bucket']
            )
            deployment_results['components']['cloudtrail'] = cloudtrail_result
            
            # 4. Deploy Lambda processors
            logger.info("Deploying Lambda functions...")
            lambda_result = self.lambda_processor.create_mcp_detection_lambda()
            deployment_results['components']['lambda'] = lambda_result
            
            # 5. Create SSM monitoring documents
            logger.info("Creating SSM documents...")
            ssm_result = self.ssm_agent.create_mcp_monitoring_document()
            deployment_results['components']['ssm'] = ssm_result
            
            deployment_results['status'] = 'success'
            logger.info("AWS MCP Detection architecture deployed successfully")
            
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            deployment_results['status'] = 'failed'
            deployment_results['error'] = str(e)
        
        return deployment_results
    
    def get_architecture_overview(self) -> Dict:
        """Get overview of the complete AWS architecture"""
        
        return {
            'architecture_name': 'AWS MCP Detection System',
            'description': 'Comprehensive AWS-based solution for detecting unauthorized MCP usage',
            'components': {
                'data_collection': [
                    'VPC Flow Logs - Network traffic analysis',
                    'CloudTrail - API activity monitoring',
                    'Systems Manager - Endpoint monitoring',
                    'GuardDuty - Threat intelligence'
                ],
                'processing': [
                    'Lambda - Real-time event processing',
                    'Kinesis - Stream processing',
                    'Athena - SQL-based analysis',
                    'OpenSearch - Log analysis and search'
                ],
                'detection': [
                    'GuardDuty - ML-based threat detection',
                    'Config - Compliance monitoring',
                    'Security Hub - Centralized findings',
                    'Network Firewall - Traffic inspection'
                ],
                'response': [
                    'EventBridge - Event routing',
                    'SNS/SQS - Alerting',
                    'Lambda - Automated remediation',
                    'Systems Manager - Endpoint response'
                ]
            },
            'data_flow': [
                '1. Network traffic captured by VPC Flow Logs',
                '2. API activities logged by CloudTrail',
                '3. Endpoint data collected by Systems Manager',
                '4. Events processed by Lambda functions',
                '5. Threats detected by GuardDuty and custom rules',
                '6. Findings centralized in Security Hub',
                '7. Alerts sent via SNS/EventBridge',
                '8. Automated responses executed via Lambda/SSM'
            ],
            'cost_optimization': [
                'Use S3 Intelligent Tiering for log storage',
                'Implement lifecycle policies for old logs',
                'Use Spot instances for batch processing',
                'Optimize Lambda memory and timeout settings'
            ]
        }

# Example usage
if __name__ == "__main__":
    # Initialize the orchestrator
    orchestrator = AWSMCPDetectionOrchestrator(region='us-east-1')
    
    # Configuration for deployment
    config = {
        'vpc_id': 'vpc-12345678',
        's3_bucket': 'mcp-detection-logs-bucket',
        'guardduty_detector_id': 'detector-12345678'
    }
    
    # Get architecture overview
    overview = orchestrator.get_architecture_overview()
    print("AWS MCP Detection Architecture Overview:")
    print(json.dumps(overview, indent=2))
    
    # Deploy the architecture (uncomment to actually deploy)
    # deployment_result = orchestrator.deploy_complete_architecture(config)
    # print("Deployment Result:")
    # print(json.dumps(deployment_result, indent=2))