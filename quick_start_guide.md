# Quick Start Implementation Guide

## 30-Minute Proof of Concept

### Prerequisites Check
```bash
# Verify you have the basics
python --version  # Should be 3.10+
aws --version     # AWS CLI v2
aws sts get-caller-identity  # Verify AWS access
```

### Step 1: Rapid Setup (5 minutes)
```bash
# Clone and setup
git clone <your-repo-url>
cd vulnerability-management-system

# Quick environment setup
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Step 2: Deploy Basic System (10 minutes)
```bash
# Configure with defaults
agentcore configure -e vulnerability_management_system.py
# When prompted:
# - Execution Role: Press Enter (auto-create)
# - ECR Repository: Press Enter (auto-create)  
# - Requirements: Press Enter (use requirements.txt)
# - OAuth: Type 'no'
# - Headers: Type 'no'
# - Memory: Type 'yes'

# Deploy
agentcore deploy
# Wait for deployment (2-3 minutes)
```

### Step 3: Test with Sample Data (10 minutes)
```bash
# Test risk prioritization with sample vulnerability data
agentcore invoke '{
  "request_type": "risk_prioritization",
  "query": "Prioritize these sample vulnerabilities",
  "data": {
    "vulnerabilities": [
      {"cve": "CVE-2024-1234", "cvss": 9.8, "asset": "web-server-01", "type": "RCE"},
      {"cve": "CVE-2024-5678", "cvss": 7.5, "asset": "workstation-05", "type": "privilege escalation"},
      {"cve": "CVE-2024-9012", "cvss": 8.1, "asset": "database-prod", "type": "SQL injection"}
    ],
    "asset_criticality": {
      "web-server-01": "critical",
      "database-prod": "critical", 
      "workstation-05": "low"
    }
  },
  "actor_id": "security-team"
}'
```

### Step 4: Test Asset Discovery (5 minutes)
```bash
# Test asset discovery with sample network data
agentcore invoke '{
  "request_type": "asset_discovery",
  "query": "Analyze sample network assets",
  "data": {
    "network_scan": [
      {"ip": "10.0.1.10", "hostname": "web-01", "os": "Ubuntu 20.04", "services": ["80", "443"]},
      {"ip": "10.0.1.20", "hostname": "db-01", "os": "Windows Server 2019", "services": ["1433", "3389"]},
      {"ip": "10.0.1.30", "hostname": "app-01", "os": "CentOS 8", "services": ["8080", "22"]}
    ]
  },
  "actor_id": "security-team"
}'
```

## 2-Hour Production-Ready Setup

### Hour 1: Enhanced Configuration

#### Connect Real Data Sources
```python
# Create data_sources.py
import pandas as pd
import json

# Sample Nessus CSV processor
def process_nessus_csv(csv_file):
    df = pd.read_csv(csv_file)
    vulnerabilities = []
    
    for _, row in df.iterrows():
        vuln = {
            "plugin_id": row.get('Plugin ID', ''),
            "cve": row.get('CVE', ''),
            "cvss": float(row.get('CVSS', 0)),
            "risk": row.get('Risk', 'Info'),
            "host": row.get('Host', ''),
            "protocol": row.get('Protocol', ''),
            "port": row.get('Port', ''),
            "name": row.get('Name', ''),
            "synopsis": row.get('Synopsis', ''),
            "description": row.get('Description', ''),
            "solution": row.get('Solution', '')
        }
        vulnerabilities.append(vuln)
    
    return vulnerabilities

# Test with your actual Nessus export
if __name__ == "__main__":
    vulns = process_nessus_csv("your_nessus_export.csv")
    
    payload = {
        "request_type": "risk_prioritization",
        "query": f"Prioritize {len(vulns)} real vulnerabilities from Nessus",
        "data": {"vulnerabilities": vulns},
        "actor_id": "security-team"
    }
    
    # Save for testing
    with open("real_vuln_payload.json", "w") as f:
        json.dump(payload, f, indent=2)
```

#### Test with Real Data
```bash
# Process your actual vulnerability scan
python data_sources.py

# Test with real data
agentcore invoke "$(cat real_vuln_payload.json)"
```

### Hour 2: Integration Setup

#### Slack Integration
```python
# slack_integration.py
import requests
import json

SLACK_WEBHOOK = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

def send_critical_alert(vulnerability_analysis):
    message = {
        "text": "🚨 Critical Vulnerability Analysis Complete",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Critical Vulnerabilities", "value": str(vulnerability_analysis.get('critical_count', 0)), "short": True},
                {"title": "High Priority", "value": str(vulnerability_analysis.get('high_count', 0)), "short": True},
                {"title": "Top Recommendation", "value": vulnerability_analysis.get('top_recommendation', 'Review results'), "short": False}
            ]
        }]
    }
    
    requests.post(SLACK_WEBHOOK, json=message)

# Test Slack integration
if __name__ == "__main__":
    test_analysis = {
        "critical_count": 5,
        "high_count": 23,
        "top_recommendation": "Patch CVE-2024-1234 on web-server-01 immediately"
    }
    send_critical_alert(test_analysis)
```

#### Email Reporting
```python
# email_reports.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_weekly_report(vm_metrics):
    msg = MIMEMultipart()
    msg['From'] = "vm-system@company.com"
    msg['To'] = "security-team@company.com"
    msg['Subject'] = "Weekly Vulnerability Management Report"
    
    body = f"""
    Weekly VM Report:
    
    • Vulnerabilities Processed: {vm_metrics.get('processed', 0)}
    • Critical Issues: {vm_metrics.get('critical', 0)}
    • Remediated This Week: {vm_metrics.get('remediated', 0)}
    • Mean Time to Remediation: {vm_metrics.get('mttr', 'N/A')} hours
    
    Top Priorities:
    {chr(10).join(vm_metrics.get('top_priorities', []))}
    """
    
    msg.attach(MIMEText(body, 'plain'))
    
    server = smtplib.SMTP('smtp.company.com', 587)
    server.starttls()
    server.login("vm-system@company.com", "password")
    server.send_message(msg)
    server.quit()
```

## Real-World Implementation Examples

### Example 1: Small Company (< 100 employees)
```bash
# Focus on automation and efficiency
# Weekly vulnerability processing workflow

#!/bin/bash
# weekly_vm_process.sh

echo "Starting weekly VM process..."

# 1. Download latest Nessus scan
scp scanner.company.com:/scans/weekly_scan.csv ./

# 2. Process with VM system
agentcore invoke '{
  "request_type": "risk_prioritization",
  "query": "Process weekly vulnerability scan",
  "data": {"scan_file": "weekly_scan.csv"},
  "actor_id": "it-team"
}'

# 3. Generate simple report
agentcore invoke '{
  "request_type": "collaboration", 
  "query": "Generate weekly report for management",
  "data": {"report_type": "executive_summary"},
  "actor_id": "it-manager"
}'

echo "Weekly VM process complete"
```

### Example 2: Medium Enterprise (500-2000 employees)
```python
# enterprise_workflow.py
# Multi-source integration with automated ticketing

import schedule
import time
from integration_examples import VulnerabilityDataProcessor, TicketingIntegration

def daily_vm_workflow():
    processor = VulnerabilityDataProcessor("https://vm-system.company.com")
    ticketing = TicketingIntegration("https://vm-system.company.com")
    
    # Process multiple sources
    nessus_results = processor.process_nessus_scan("/scans/daily/nessus.xml")
    qualys_results = processor.process_qualys_api(qualys_config)
    aws_results = processor.process_aws_inspector("us-west-2")
    
    # Create tickets for critical issues
    all_critical = []
    for result in [nessus_results, qualys_results, aws_results]:
        all_critical.extend(result.get('critical_vulnerabilities', []))
    
    if all_critical:
        tickets = ticketing.create_jira_tickets(all_critical)
        print(f"Created {len(tickets)} tickets for critical vulnerabilities")

# Schedule daily processing
schedule.every().day.at("06:00").do(daily_vm_workflow)

while True:
    schedule.run_pending()
    time.sleep(3600)  # Check every hour
```

### Example 3: Large Enterprise (5000+ employees)
```yaml
# kubernetes_deployment.yaml
# Scalable microservices deployment

apiVersion: apps/v1
kind: Deployment
metadata:
  name: vm-orchestrator
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vm-orchestrator
  template:
    metadata:
      labels:
        app: vm-orchestrator
    spec:
      containers:
      - name: vm-system
        image: vm-system:latest
        env:
        - name: BEDROCK_AGENTCORE_MEMORY_ID
          valueFrom:
            secretKeyRef:
              name: vm-secrets
              key: memory-id
        - name: AWS_REGION
          value: "us-west-2"
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi" 
            cpu: "2000m"
---
apiVersion: v1
kind: Service
metadata:
  name: vm-orchestrator-service
spec:
  selector:
    app: vm-orchestrator
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

## Monitoring and Success Metrics

### Basic Monitoring Setup
```python
# monitoring.py
import boto3
import time

def publish_vm_metrics(processed_count, critical_count, mttr_hours):
    cloudwatch = boto3.client('cloudwatch')
    
    cloudwatch.put_metric_data(
        Namespace='VulnerabilityManagement',
        MetricData=[
            {
                'MetricName': 'VulnerabilitiesProcessed',
                'Value': processed_count,
                'Unit': 'Count',
                'Timestamp': time.time()
            },
            {
                'MetricName': 'CriticalVulnerabilities',
                'Value': critical_count,
                'Unit': 'Count',
                'Timestamp': time.time()
            },
            {
                'MetricName': 'MeanTimeToRemediation',
                'Value': mttr_hours,
                'Unit': 'Count',
                'Timestamp': time.time()
            }
        ]
    )

# Usage after each VM system call
publish_vm_metrics(processed_count=150, critical_count=5, mttr_hours=24)
```

### Success Criteria Checklist
- [ ] System processes vulnerability scans in < 5 minutes
- [ ] Reduces vulnerability backlog by 50% in first month
- [ ] Decreases false positive alerts by 70%
- [ ] Improves team productivity metrics by 40%
- [ ] Achieves 90% user adoption within 60 days
- [ ] Integrates with existing tools (SIEM, ticketing, dashboards)
- [ ] Provides clear ROI demonstration within 90 days

## Troubleshooting Common Issues

### Issue: Memory not persisting data
```bash
# Check memory status
agentcore status

# Verify memory is ACTIVE
aws bedrock-agentcore describe-memory --memory-id YOUR_MEMORY_ID

# Wait for memory extraction (15-30 seconds after storing data)
sleep 30
```

### Issue: Integration failures
```python
# Test connectivity
import requests

def test_integration(endpoint):
    try:
        response = requests.get(f"{endpoint}/health", timeout=10)
        print(f"✅ {endpoint} - Status: {response.status_code}")
    except Exception as e:
        print(f"❌ {endpoint} - Error: {e}")

# Test all integrations
test_integration("https://your-vm-system.amazonaws.com")
test_integration("https://company.atlassian.net")
test_integration("https://company.service-now.com")
```

### Issue: Performance optimization
```bash
# Monitor system performance
aws logs tail /aws/bedrock-agentcore/runtimes/YOUR_AGENT_ID --follow

# Check CloudWatch metrics
aws cloudwatch get-metric-statistics \
  --namespace VulnerabilityManagement \
  --metric-name VulnerabilitiesProcessed \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-01-03T23:59:59Z \
  --period 3600 \
  --statistics Sum
```

This guide provides multiple implementation paths from a 30-minute proof of concept to enterprise-scale deployment. Start small, prove value, then scale based on your organization's needs and success metrics.