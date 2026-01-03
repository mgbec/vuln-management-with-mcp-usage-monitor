#!/bin/bash

# 30-Minute POC Quick Start Script
# Integrated Vulnerability Management & AI Usage Monitoring System

echo "🚀 Starting 30-Minute Integrated VM & AI Monitoring POC Setup"
echo "=============================================================="

# Check Python version
echo "📋 Checking Python version..."
python_version=$(python3 --version 2>&1)
if [[ $? -eq 0 ]]; then
    echo "✅ Python found: $python_version"
else
    echo "❌ Python 3 not found. Please install Python 3.8+ and try again."
    exit 1
fi

# Create virtual environment
echo "🔧 Creating virtual environment..."
python3 -m venv poc_venv
if [[ $? -eq 0 ]]; then
    echo "✅ Virtual environment created"
else
    echo "❌ Failed to create virtual environment"
    exit 1
fi

# Activate virtual environment
echo "🔌 Activating virtual environment..."
source poc_venv/bin/activate
if [[ $? -eq 0 ]]; then
    echo "✅ Virtual environment activated"
else
    echo "❌ Failed to activate virtual environment"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install flask pandas sqlite3 requests psutil watchdog

# Check if all files exist
echo "📁 Checking required files..."
required_files=("poc_integrated_system.py" "poc_requirements.txt")
for file in "${required_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo "✅ Found: $file"
    else
        echo "❌ Missing: $file"
        echo "Please ensure all POC files are in the current directory"
        exit 1
    fi
done

# Create startup script
echo "📝 Creating startup script..."
cat > start_poc.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting Integrated VM & AI Monitoring POC"
echo "=============================================="

# Activate virtual environment
source poc_venv/bin/activate

# Start the POC system
echo "🔍 Starting integrated monitoring system..."
python3 poc_integrated_system.py

EOF

chmod +x start_poc.sh

# Create demo data script
echo "📊 Creating demo data generator..."
cat > generate_demo_data.py << 'EOF'
#!/usr/bin/env python3
"""
Generate additional demo data for POC
"""
import sqlite3
import json
from datetime import datetime, timedelta
import random

def generate_demo_data():
    conn = sqlite3.connect("poc_integrated.db")
    cursor = conn.cursor()
    
    # Generate additional AI usage events
    ai_tools = ["ChatGPT", "Claude", "GitHub Copilot", "Microsoft Copilot", "Bard"]
    users = ["alice@company.com", "bob@company.com", "charlie@company.com", "diana@company.com"]
    activities = ["code_generation", "document_analysis", "data_processing", "content_creation"]
    
    for i in range(20):
        timestamp = (datetime.utcnow() - timedelta(hours=random.randint(1, 168))).isoformat()
        user = random.choice(users)
        tool = random.choice(ai_tools)
        activity = random.choice(activities)
        risk_level = random.choice(["low", "medium", "high"])
        sensitive_data = random.choice([True, False])
        violations = ["external_ai_usage"] if sensitive_data else []
        
        cursor.execute('''
            INSERT INTO ai_usage_events 
            (timestamp, user_id, ai_tool, activity_type, risk_level, 
             sensitive_data_detected, policy_violations, session_duration, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp, user, tool, activity, risk_level,
            sensitive_data, json.dumps(violations), 
            random.randint(10, 180), f"demo_{i}_{int(datetime.now().timestamp())}"
        ))
    
    # Generate additional MCP events
    servers = ["filesystem-server", "database-server", "web-server", "api-server"]
    tools = ["read_file", "write_file", "execute_command", "query_data", "list_directory"]
    methods = ["tools/call", "resources/read", "resources/write"]
    
    for i in range(15):
        timestamp = (datetime.utcnow() - timedelta(hours=random.randint(1, 72))).isoformat()
        user = random.choice(users)
        server = random.choice(servers)
        tool = random.choice(tools)
        method = random.choice(methods)
        risk_level = random.choice(["low", "medium", "high"])
        
        # Add vulnerability patterns for some events
        vuln_patterns = []
        if risk_level == "high" and random.random() < 0.3:
            vuln_patterns = random.choice([["command_injection"], ["credential_exposure"], []])
        
        cursor.execute('''
            INSERT INTO mcp_events 
            (timestamp, session_id, user_id, server_name, tool_name, method,
             success, risk_level, vulnerability_patterns)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp, f"demo_session_{i}", user, server, tool, method,
            random.choice([True, False]), risk_level, json.dumps(vuln_patterns)
        ))
    
    conn.commit()
    conn.close()
    print(f"✅ Generated 20 AI usage events and 15 MCP events")

if __name__ == "__main__":
    generate_demo_data()
EOF

chmod +x generate_demo_data.py

# Create test script
echo "🧪 Creating test script..."
cat > test_poc.py << 'EOF'
#!/usr/bin/env python3
"""
Test the POC system functionality
"""
import requests
import json
import time

def test_poc_endpoints():
    base_url = "http://localhost:5000"
    
    endpoints = [
        "/vulnerabilities",
        "/ai-usage", 
        "/mcp-events",
        "/alerts",
        "/dashboard"
    ]
    
    print("🧪 Testing POC endpoints...")
    
    for endpoint in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                print(f"✅ {endpoint}: {response.status_code} - {len(data)} items")
            else:
                print(f"❌ {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"❌ {endpoint}: Connection failed - {e}")
    
    # Test event simulation
    print("\n🎯 Testing event simulation...")
    try:
        sim_response = requests.post(f"{base_url}/simulate-event", data={
            'event_type': 'ai',
            'risk_level': 'high',
            'include_vulnerability': 'true'
        }, timeout=5)
        
        if sim_response.status_code == 200:
            print("✅ Event simulation: Success")
        else:
            print(f"❌ Event simulation: {sim_response.status_code}")
    except Exception as e:
        print(f"❌ Event simulation: {e}")

if __name__ == "__main__":
    print("Waiting for POC system to start...")
    time.sleep(5)
    test_poc_endpoints()
EOF

chmod +x test_poc.py

echo ""
echo "✅ POC Setup Complete!"
echo "======================"
echo ""
echo "🎯 Quick Start Commands:"
echo "   1. Start POC:           ./start_poc.sh"
echo "   2. Generate demo data:  python3 generate_demo_data.py"
echo "   3. Test endpoints:      python3 test_poc.py"
echo ""
echo "🌐 Web Interface (after starting):"
echo "   • Main Dashboard:       http://localhost:5000"
echo "   • Vulnerabilities:      http://localhost:5000/vulnerabilities"
echo "   • AI Usage Events:      http://localhost:5000/ai-usage"
echo "   • MCP Events:           http://localhost:5000/mcp-events"
echo "   • Active Alerts:        http://localhost:5000/alerts"
echo "   • Executive Dashboard:  http://localhost:5000/dashboard"
echo "   • Event Simulator:      http://localhost:5000/simulate-event"
echo ""
echo "📋 Demo Workflow:"
echo "   1. Run: ./start_poc.sh"
echo "   2. Open: http://localhost:5000 in browser"
echo "   3. Explore vulnerabilities and events"
echo "   4. Simulate new events to see real-time processing"
echo "   5. View integrated dashboard metrics"
echo ""
echo "🚀 Ready to start! Run: ./start_poc.sh"