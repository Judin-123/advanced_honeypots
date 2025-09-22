"""
Monitoring Dashboard for ML-Powered Honeypot
Flask-based web interface for visualizing system status and adaptation events
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from flask import Flask, render_template, jsonify, request
import pandas as pd
from elasticsearch import Elasticsearch
import os

logger = logging.getLogger(__name__)

class HoneypotDashboard:
    """Web dashboard for monitoring honeypot operations and ML adaptations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.app = Flask(__name__)
        self.es_client = None
        self._setup_elasticsearch()
        self._setup_routes()
    
    def _setup_elasticsearch(self):
        """Initialize Elasticsearch connection"""
        try:
            es_config = self.config.get("elasticsearch", {})
            # Use the newer Elasticsearch client format
            self.es_client = Elasticsearch(
                hosts=[{
                    'host': es_config.get('host', 'localhost'),
                    'port': es_config.get('port', 9200),
                    'scheme': 'http'
                }]
            )
            
            # Test connection
            if self.es_client.ping():
                logger.info("Connected to Elasticsearch")
            else:
                logger.warning("Could not connect to Elasticsearch")
                self.es_client = None
        except Exception as e:
            logger.error(f"Failed to setup Elasticsearch: {e}")
            self.es_client = None
    
    def _setup_routes(self):
        """Setup Flask routes for the dashboard"""
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('dashboard.html')
        
        @self.app.route('/api/status')
        def get_status():
            """Get overall system status"""
            return jsonify(self._get_system_status())
        
        @self.app.route('/api/adaptations')
        def get_adaptations():
            """Get adaptation history"""
            limit = request.args.get('limit', 50, type=int)
            return jsonify(self._get_adaptation_history(limit))
        
        @self.app.route('/api/threats')
        def get_threats():
            """Get recent threat classifications"""
            hours = request.args.get('hours', 24, type=int)
            return jsonify(self._get_recent_threats(hours))
        
        @self.app.route('/api/metrics')
        def get_metrics():
            """Get system metrics"""
            return jsonify(self._get_system_metrics())
        
        @self.app.route('/api/sessions')
        def get_sessions():
            """Get recent session data"""
            limit = request.args.get('limit', 100, type=int)
            return jsonify(self._get_recent_sessions(limit))
        
        @self.app.route('/api/force-adaptation', methods=['POST'])
        def force_adaptation():
            """Force adaptation to specific profile"""
            data = request.get_json()
            profile = data.get('profile', 'standard')
            # This would integrate with the adaptation engine
            return jsonify({"status": "success", "profile": profile})
    
    def _get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        try:
            # Check Elasticsearch status
            es_status = "connected" if self.es_client and self.es_client.ping() else "disconnected"
            
            # Get recent activity
            recent_sessions = self._get_recent_sessions(10)
            recent_adaptations = self._get_adaptation_history(5)
            
            # Calculate uptime (simplified)
            uptime = "24h 15m"  # This would be calculated from actual start time
            
            return {
                "status": "operational",
                "elasticsearch": es_status,
                "uptime": uptime,
                "recent_sessions": len(recent_sessions),
                "recent_adaptations": len(recent_adaptations),
                "current_profile": self._get_current_profile(),
                "last_update": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {"status": "error", "error": str(e)}
    
    def _get_adaptation_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get adaptation history from file or Elasticsearch"""
        try:
            # Try to load from file first
            history_path = "data/adaptation_history.json"
            if os.path.exists(history_path):
                with open(history_path, 'r') as f:
                    history = json.load(f)
                return history[-limit:] if history else []
            
            # Fallback to Elasticsearch if available
            if self.es_client:
                query = {
                    "query": {"match_all": {}},
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "size": limit
                }
                
                response = self.es_client.search(
                    index="honeypot-adaptations",
                    body=query
                )
                
                return [hit["_source"] for hit in response["hits"]["hits"]]
            
            return []
        except Exception as e:
            logger.error(f"Error getting adaptation history: {e}")
            return []
    
    def _get_recent_threats(self, hours: int = 24) -> Dict[str, Any]:
        """Get recent threat classifications"""
        try:
            if not self.es_client:
                return {"error": "Elasticsearch not available"}
            
            # Query for recent threat classifications
            query = {
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": f"now-{hours}h"
                        }
                    }
                },
                "aggs": {
                    "threat_levels": {
                        "terms": {
                            "field": "threat_level.keyword"
                        }
                    },
                    "confidence_distribution": {
                        "histogram": {
                            "field": "confidence",
                            "interval": 0.1
                        }
                    }
                }
            }
            
            response = self.es_client.search(
                index="honeypot-threats",
                body=query
            )
            
            return {
                "threat_distribution": response["aggregations"]["threat_levels"]["buckets"],
                "confidence_distribution": response["aggregations"]["confidence_distribution"]["buckets"],
                "total_classifications": response["hits"]["total"]["value"]
            }
        except Exception as e:
            logger.error(f"Error getting recent threats: {e}")
            return {"error": str(e)}
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics"""
        try:
            if not self.es_client:
                return {"error": "Elasticsearch not available"}
            
            # Get metrics from last 24 hours
            query = {
                "query": {
                    "range": {
                        "timestamp": {
                            "gte": "now-24h"
                        }
                    }
                },
                "aggs": {
                    "sessions_per_hour": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "hour"
                        }
                    },
                    "avg_session_duration": {
                        "avg": {
                            "field": "session_duration"
                        }
                    },
                    "total_commands": {
                        "sum": {
                            "field": "command_count"
                        }
                    }
                }
            }
            
            response = self.es_client.search(
                index="honeypot-sessions",
                body=query
            )
            
            return {
                "sessions_per_hour": response["aggregations"]["sessions_per_hour"]["buckets"],
                "avg_session_duration": response["aggregations"]["avg_session_duration"]["value"],
                "total_commands": response["aggregations"]["total_commands"]["value"],
                "total_sessions": response["hits"]["total"]["value"]
            }
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return {"error": str(e)}
    
    def _get_recent_sessions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent session data"""
        try:
            if not self.es_client:
                return []
            
            query = {
                "query": {"match_all": {}},
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": limit
            }
            
            response = self.es_client.search(
                index="honeypot-sessions",
                body=query
            )
            
            return [hit["_source"] for hit in response["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Error getting recent sessions: {e}")
            return []
    
    def _get_current_profile(self) -> str:
        """Get current honeypot profile"""
        # This would read from the adaptation engine or config
        return "standard"  # Default fallback
    
    def run(self, host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
        """Run the dashboard server"""
        logger.info(f"Starting dashboard on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)
    
    def create_html_template(self):
        """Create HTML template for the dashboard"""
        template_dir = "templates"
        os.makedirs(template_dir, exist_ok=True)
        
        html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ML-Powered Honeypot Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .status-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .status-card h3 { margin-top: 0; color: #2c3e50; }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; }
        .metric-value { font-weight: bold; color: #27ae60; }
        .chart-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .adaptation-log { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .adaptation-item { border-left: 4px solid #3498db; padding: 10px; margin: 10px 0; background: #f8f9fa; }
        .threat-scanner { border-left-color: #f39c12; }
        .threat-amateur { border-left-color: #e74c3c; }
        .threat-advanced { border-left-color: #8e44ad; }
        .refresh-btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
        .refresh-btn:hover { background: #2980b9; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕷️ ML-Powered Honeypot Dashboard</h1>
            <p>Real-time monitoring of adaptive honeypot behavior</p>
            <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
        </div>
        
        <div class="status-grid">
            <div class="status-card">
                <h3>System Status</h3>
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
                <h3>Recent Activity</h3>
                <div class="metric">
                    <span>Sessions (24h):</span>
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
            <h3>Threat Classification Distribution</h3>
            <canvas id="threatChart" width="400" height="200"></canvas>
        </div>
        
        <div class="chart-container">
            <h3>Session Activity (Last 24 Hours)</h3>
            <canvas id="activityChart" width="400" height="200"></canvas>
        </div>
        
        <div class="adaptation-log">
            <h3>Recent Adaptations</h3>
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
                document.getElementById('current-profile').textContent = status.current_profile;
                document.getElementById('recent-sessions').textContent = status.recent_sessions;
                document.getElementById('recent-adaptations').textContent = status.recent_adaptations;
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
                        labels: threats.threat_distribution.map(b => b.key),
                        datasets: [{
                            data: threats.threat_distribution.map(b => b.doc_count),
                            backgroundColor: ['#f39c12', '#e74c3c', '#8e44ad']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
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
                        labels: metrics.sessions_per_hour.map(b => new Date(b.key_as_string).toLocaleTimeString()),
                        datasets: [{
                            label: 'Sessions',
                            data: metrics.sessions_per_hour.map(b => b.doc_count),
                            borderColor: '#3498db',
                            backgroundColor: 'rgba(52, 152, 219, 0.1)',
                            fill: true
                        }]
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }
        }
        
        async function updateAdaptations() {
            const adaptations = await fetchData('/api/adaptations?limit=10');
            if (adaptations) {
                const list = document.getElementById('adaptation-list');
                list.innerHTML = adaptations.map(adapt => `
                    <div class="adaptation-item threat-${adapt.new_profile}">
                        <strong>${new Date(adapt.timestamp).toLocaleString()}</strong><br>
                        ${adapt.old_profile} → ${adapt.new_profile}<br>
                        <small>${adapt.reason}</small>
                    </div>
                `).join('');
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
</html>
        """
        
        with open(f"{template_dir}/dashboard.html", 'w') as f:
            f.write(html_content)
        
        logger.info("Created dashboard HTML template")
