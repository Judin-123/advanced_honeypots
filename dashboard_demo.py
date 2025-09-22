"""
ML-Powered Honeypot Dashboard Demo
Simple Flask dashboard for demonstration
"""

import sys
import os
import json
import time
from datetime import datetime, timedelta
import random

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# Mock data for demonstration
mock_data = {
    "system_status": {
        "status": "operational",
        "uptime": "2h 15m",
        "current_profile": "minimal",
        "sessions_today": 47,
        "adaptations_today": 3,
        "elasticsearch": "connected"
    },
    "recent_adaptations": [
        {
            "timestamp": "2024-01-15T14:30:00Z",
            "old_profile": "standard",
            "new_profile": "minimal",
            "reason": "High proportion of scanners detected - switching to minimal profile to conserve resources"
        },
        {
            "timestamp": "2024-01-15T13:45:00Z",
            "old_profile": "deception",
            "new_profile": "standard",
            "reason": "Threat level normalized - returning to standard profile"
        },
        {
            "timestamp": "2024-01-15T12:20:00Z",
            "old_profile": "standard",
            "new_profile": "deception",
            "reason": "Advanced threats detected - switching to deception profile with enhanced countermeasures"
        }
    ],
    "threat_distribution": [
        {"threat_level": "scanner", "count": 28, "percentage": 59.6},
        {"threat_level": "amateur", "count": 15, "percentage": 31.9},
        {"threat_level": "advanced", "count": 4, "percentage": 8.5}
    ],
    "recent_sessions": [
        {
            "timestamp": "2024-01-15T14:35:00Z",
            "session_id": "scanner_047",
            "src_ip": "192.168.1.100",
            "threat_level": "scanner",
            "confidence": 0.92,
            "commands": 3,
            "duration": 25
        },
        {
            "timestamp": "2024-01-15T14:32:00Z",
            "session_id": "amateur_023",
            "src_ip": "192.168.1.101",
            "threat_level": "amateur",
            "confidence": 0.87,
            "commands": 7,
            "duration": 45
        },
        {
            "timestamp": "2024-01-15T14:28:00Z",
            "session_id": "advanced_008",
            "src_ip": "192.168.1.102",
            "threat_level": "advanced",
            "confidence": 0.95,
            "commands": 12,
            "duration": 120
        }
    ]
}

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    """Get system status"""
    return jsonify(mock_data["system_status"])

@app.route('/api/adaptations')
def get_adaptations():
    """Get adaptation history"""
    limit = request.args.get('limit', 10, type=int)
    return jsonify(mock_data["recent_adaptations"][:limit])

@app.route('/api/threats')
def get_threats():
    """Get threat distribution"""
    return jsonify({
        "threat_distribution": mock_data["threat_distribution"],
        "total_sessions": sum(t["count"] for t in mock_data["threat_distribution"])
    })

@app.route('/api/sessions')
def get_sessions():
    """Get recent sessions"""
    limit = request.args.get('limit', 10, type=int)
    return jsonify(mock_data["recent_sessions"][:limit])

@app.route('/api/metrics')
def get_metrics():
    """Get system metrics"""
    # Generate some mock time-series data
    hours = []
    sessions_per_hour = []
    
    for i in range(24):
        hour = datetime.now() - timedelta(hours=23-i)
        hours.append(hour.strftime("%H:00"))
        # Generate realistic session counts
        base_count = random.randint(1, 5)
        if 9 <= hour.hour <= 17:  # Business hours
            base_count += random.randint(2, 4)
        sessions_per_hour.append(base_count)
    
    return jsonify({
        "sessions_per_hour": [
            {"hour": hour, "count": count} 
            for hour, count in zip(hours, sessions_per_hour)
        ],
        "total_sessions": sum(sessions_per_hour),
        "avg_session_duration": 45.2
    })

@app.route('/api/force-adaptation', methods=['POST'])
def force_adaptation():
    """Force adaptation to specific profile"""
    data = request.get_json()
    profile = data.get('profile', 'standard')
    
    # Simulate adaptation
    old_profile = mock_data["system_status"]["current_profile"]
    mock_data["system_status"]["current_profile"] = profile
    
    adaptation = {
        "timestamp": datetime.now().isoformat(),
        "old_profile": old_profile,
        "new_profile": profile,
        "reason": f"Manual adaptation to {profile} profile"
    }
    
    mock_data["recent_adaptations"].insert(0, adaptation)
    
    return jsonify({
        "status": "success",
        "adaptation": adaptation
    })

def create_html_template():
    """Create the dashboard HTML template"""
    template_dir = "templates"
    os.makedirs(template_dir, exist_ok=True)
    
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ML-Powered Honeypot Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
        }
        .header { 
            background: rgba(255,255,255,0.95); 
            color: #2c3e50; 
            padding: 30px; 
            border-radius: 15px; 
            margin-bottom: 30px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            text-align: center;
        }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header p { margin: 10px 0 0 0; font-size: 1.2em; color: #7f8c8d; }
        .status-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); 
            gap: 25px; 
            margin-bottom: 30px; 
        }
        .status-card { 
            background: rgba(255,255,255,0.95); 
            padding: 25px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }
        .status-card:hover { transform: translateY(-5px); }
        .status-card h3 { 
            margin-top: 0; 
            color: #2c3e50; 
            font-size: 1.4em;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .metric { 
            display: flex; 
            justify-content: space-between; 
            margin: 15px 0; 
            padding: 10px;
            background: rgba(52, 152, 219, 0.1);
            border-radius: 8px;
        }
        .metric-value { 
            font-weight: bold; 
            color: #27ae60; 
            font-size: 1.1em;
        }
        .chart-container { 
            background: rgba(255,255,255,0.95); 
            padding: 25px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.1); 
            margin-bottom: 30px; 
        }
        .chart-container h3 { 
            color: #2c3e50; 
            margin-top: 0;
            font-size: 1.4em;
        }
        .adaptation-log { 
            background: rgba(255,255,255,0.95); 
            padding: 25px; 
            border-radius: 15px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.1); 
        }
        .adaptation-item { 
            border-left: 4px solid #3498db; 
            padding: 15px; 
            margin: 15px 0; 
            background: rgba(52, 152, 219, 0.05); 
            border-radius: 8px;
            transition: all 0.3s ease;
        }
        .adaptation-item:hover { background: rgba(52, 152, 219, 0.1); }
        .threat-scanner { border-left-color: #f39c12; }
        .threat-amateur { border-left-color: #e74c3c; }
        .threat-advanced { border-left-color: #8e44ad; }
        .refresh-btn { 
            background: linear-gradient(45deg, #3498db, #2980b9); 
            color: white; 
            border: none; 
            padding: 12px 25px; 
            border-radius: 25px; 
            cursor: pointer; 
            font-size: 1em;
            transition: all 0.3s ease;
        }
        .refresh-btn:hover { 
            background: linear-gradient(45deg, #2980b9, #1f4e79);
            transform: translateY(-2px);
        }
        .profile-badge {
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.9em;
        }
        .profile-minimal { background: #f39c12; color: white; }
        .profile-standard { background: #3498db; color: white; }
        .profile-deception { background: #8e44ad; color: white; }
        .controls {
            margin: 20px 0;
            text-align: center;
        }
        .control-btn {
            background: linear-gradient(45deg, #e74c3c, #c0392b);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 20px;
            cursor: pointer;
            margin: 0 10px;
            transition: all 0.3s ease;
        }
        .control-btn:hover {
            background: linear-gradient(45deg, #c0392b, #a93226);
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕷️ ML-Powered Honeypot Dashboard</h1>
            <p>Real-time monitoring of adaptive honeypot behavior</p>
            <div class="controls">
                <button class="refresh-btn" onclick="refreshData()">🔄 Refresh Data</button>
                <button class="control-btn" onclick="forceAdaptation('minimal')">Minimal Profile</button>
                <button class="control-btn" onclick="forceAdaptation('standard')">Standard Profile</button>
                <button class="control-btn" onclick="forceAdaptation('deception')">Deception Profile</button>
            </div>
        </div>
        
        <div class="status-grid">
            <div class="status-card">
                <h3>📊 System Status</h3>
                <div class="metric">
                    <span>Status:</span>
                    <span class="metric-value" id="system-status">Loading...</span>
                </div>
                <div class="metric">
                    <span>Uptime:</span>
                    <span class="metric-value" id="uptime">Loading...</span>
                </div>
                <div class="metric">
                    <span>Current Profile:</span>
                    <span class="metric-value" id="current-profile">Loading...</span>
                </div>
            </div>
            
            <div class="status-card">
                <h3>📈 Activity Today</h3>
                <div class="metric">
                    <span>Sessions:</span>
                    <span class="metric-value" id="recent-sessions">Loading...</span>
                </div>
                <div class="metric">
                    <span>Adaptations:</span>
                    <span class="metric-value" id="recent-adaptations">Loading...</span>
                </div>
                <div class="metric">
                    <span>Elasticsearch:</span>
                    <span class="metric-value" id="es-status">Loading...</span>
                </div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3>🎯 Threat Classification Distribution</h3>
            <canvas id="threatChart" width="400" height="200"></canvas>
        </div>
        
        <div class="chart-container">
            <h3>📊 Session Activity (Last 24 Hours)</h3>
            <canvas id="activityChart" width="400" height="200"></canvas>
        </div>
        
        <div class="adaptation-log">
            <h3>⚡ Recent Adaptations</h3>
            <div id="adaptation-list">Loading...</div>
        </div>
    </div>
    
    <script>
        let threatChart, activityChart;
        
        async function fetchData(url) {
            try {
                const response = await fetch(url);
                return await response.json();
            } catch (error) {
                console.error('Error fetching data:', error);
                return null;
            }
        }
        
        async function updateStatus() {
            const status = await fetchData('/api/status');
            if (status) {
                document.getElementById('system-status').textContent = status.status;
                document.getElementById('uptime').textContent = status.uptime;
                document.getElementById('current-profile').innerHTML = 
                    `<span class="profile-badge profile-${status.current_profile}">${status.current_profile.toUpperCase()}</span>`;
                document.getElementById('recent-sessions').textContent = status.sessions_today;
                document.getElementById('recent-adaptations').textContent = status.adaptations_today;
                document.getElementById('es-status').textContent = status.elasticsearch;
            }
        }
        
        async function updateThreatChart() {
            const threats = await fetchData('/api/threats');
            if (threats && threats.threat_distribution) {
                const ctx = document.getElementById('threatChart').getContext('2d');
                
                if (threatChart) {
                    threatChart.destroy();
                }
                
                threatChart = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: threats.threat_distribution.map(t => t.threat_level.toUpperCase()),
                        datasets: [{
                            data: threats.threat_distribution.map(t => t.count),
                            backgroundColor: ['#f39c12', '#e74c3c', '#8e44ad'],
                            borderWidth: 3,
                            borderColor: '#fff'
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    padding: 20,
                                    font: { size: 14 }
                                }
                            }
                        }
                    }
                });
            }
        }
        
        async function updateActivityChart() {
            const metrics = await fetchData('/api/metrics');
            if (metrics && metrics.sessions_per_hour) {
                const ctx = document.getElementById('activityChart').getContext('2d');
                
                if (activityChart) {
                    activityChart.destroy();
                }
                
                activityChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: metrics.sessions_per_hour.map(h => h.hour),
                        datasets: [{
                            label: 'Sessions',
                            data: metrics.sessions_per_hour.map(h => h.count),
                            borderColor: '#3498db',
                            backgroundColor: 'rgba(52, 152, 219, 0.1)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 3
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: { color: 'rgba(0,0,0,0.1)' }
                            },
                            x: {
                                grid: { color: 'rgba(0,0,0,0.1)' }
                            }
                        },
                        plugins: {
                            legend: {
                                labels: { font: { size: 14 } }
                            }
                        }
                    }
                });
            }
        }
        
        async function updateAdaptations() {
            const adaptations = await fetchData('/api/adaptations?limit=5');
            if (adaptations) {
                const list = document.getElementById('adaptation-list');
                list.innerHTML = adaptations.map(adapt => `
                    <div class="adaptation-item threat-${adapt.new_profile}">
                        <strong>${new Date(adapt.timestamp).toLocaleString()}</strong><br>
                        <span class="profile-badge profile-${adapt.old_profile}">${adapt.old_profile.toUpperCase()}</span> 
                        → 
                        <span class="profile-badge profile-${adapt.new_profile}">${adapt.new_profile.toUpperCase()}</span><br>
                        <small>${adapt.reason}</small>
                    </div>
                `).join('');
            }
        }
        
        async function forceAdaptation(profile) {
            try {
                const response = await fetch('/api/force-adaptation', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ profile: profile })
                });
                const result = await response.json();
                if (result.status === 'success') {
                    alert(`Successfully switched to ${profile} profile!`);
                    refreshData();
                }
            } catch (error) {
                console.error('Error forcing adaptation:', error);
            }
        }
        
        async function refreshData() {
            await Promise.all([
                updateStatus(),
                updateThreatChart(),
                updateActivityChart(),
                updateAdaptations()
            ]);
        }
        
        // Initial load
        refreshData();
        
        // Auto-refresh every 30 seconds
        setInterval(refreshData, 30000);
    </script>
</body>
</html>"""
    
    with open(f"{template_dir}/dashboard.html", 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print("✅ Dashboard HTML template created")

def main():
    """Run the dashboard demo"""
    print("🚀 Starting ML-Powered Honeypot Dashboard Demo")
    print("=" * 50)
    
    # Create the HTML template
    create_html_template()
    
    print("📊 Dashboard features:")
    print("   • Real-time system status")
    print("   • Threat distribution visualization")
    print("   • Session activity charts")
    print("   • Adaptation history")
    print("   • Manual profile switching")
    print()
    print("🌐 Access the dashboard at: http://localhost:5000")
    print("🔄 Auto-refresh every 30 seconds")
    print("⚡ Try the manual profile switching buttons!")
    print()
    print("Press Ctrl+C to stop the server")
    print()
    
    # Start the Flask server
    app.run(host="0.0.0.0", port=5000, debug=False)

if __name__ == "__main__":
    main()
