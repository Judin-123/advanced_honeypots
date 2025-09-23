"""
Simple Web Interface for ML-Powered Honeypot
"""
from flask import Flask, render_template, jsonify, request, send_from_directory
import os
import requests
import json
import random
from datetime import datetime, timedelta
import threading
import time

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Configuration
CONFIG = {
    'ml_service_url': 'http://localhost:5001',
    'port': 5000,
    'debug': True
}

# In-memory storage for demo purposes
threat_logs = []

# Serve static files
@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/')
def index():
    """Render the main dashboard"""
    # Temporary: return simple response to isolate template issues
    return "OK: server running", 200

@app.route('/page')
def page():
    try:
        return render_template('index.html')
    except Exception as e:
        app.logger.exception("Template render failed")
        return f"Template error: {e}", 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "time": datetime.now().isoformat()})

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get recent threats"""
    return jsonify({
        'threats': threat_logs[-50:],  # Return last 50 threats
        'total': len(threat_logs),
        'last_updated': datetime.now().isoformat()
    })

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyze a request for threats"""
    try:
        data = request.get_json()
        
        # Example feature extraction (in a real app, this would be more sophisticated)
        features = extract_features(data)
        
        # Get prediction from ML service
        try:
            response = requests.post(
                f"{CONFIG['ml_service_url']}/predict",
                json={'features': features},
                timeout=5
            )
            result = response.json()
        except Exception as e:
            result = {
                'is_threat': random.random() > 0.7,  # Random for demo if ML service is down
                'confidence': random.random(),
                'error': str(e)
            }
        
        # Log the threat
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': data.get('source_ip', 'unknown'),
            'is_threat': result.get('is_threat', False),
            'confidence': result.get('confidence', 0.0),
            'details': {
                'path': data.get('path', '/'),
                'method': data.get('method', 'GET'),
                'user_agent': data.get('user_agent', 'Unknown')
            }
        }
        
        threat_logs.append(log_entry)
        
        return jsonify({
            'success': True,
            'is_threat': log_entry['is_threat'],
            'confidence': log_entry['confidence']
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def extract_features(request_data):
    """Extract features from the request for the ML model"""
    # This is a simplified example. In a real app, you'd extract meaningful features
    # from the request data that your model was trained on.
    return [
        len(request_data.get('path', '')),  # Length of the path
        len(request_data.get('user_agent', '')),  # Length of user agent
        int('..' in request_data.get('path', '')),  # Path traversal attempt
        int('SELECT' in request_data.get('query', '').upper()),  # SQL injection attempt
        int('<script>' in request_data.get('data', '').lower())  # XSS attempt
    ]

def generate_demo_data():
    """Generate demo threat data"""
    threats = [
        'SQL Injection Attempt',
        'XSS Attack',
        'Path Traversal',
        'Brute Force Login',
        'Command Injection'
    ]
    
    while True:
        time.sleep(random.uniform(1, 5))  # Random delay between 1-5 seconds
        
        threat = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': f"192.168.1.{random.randint(1, 255)}",
            'threat_type': random.choice(threats),
            'severity': random.choice(['Low', 'Medium', 'High', 'Critical']),
            'details': {
                'path': f"/{'/'.join(random.choice(['admin', 'login', 'api', 'wp-admin']) for _ in range(random.randint(1, 3)))}",
                'method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
                'user_agent': random.choice([
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                    'python-requests/2.25.1',
                    'curl/7.68.0',
                    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
                ])
            },
            'is_threat': True,
            'confidence': round(random.uniform(0.6, 0.99), 2)
        }
        
        threat_logs.append(threat)
        
        # Keep only the last 1000 entries
        if len(threat_logs) > 1000:
            threat_logs.pop(0)

if __name__ == '__main__':
    # Start demo data generator in a separate thread
    demo_thread = threading.Thread(target=generate_demo_data, daemon=True)
    demo_thread.start()
    
    # Start the web server
    print(f"Starting web interface on http://localhost:{CONFIG['port']}")
    app.run(host='0.0.0.0', port=CONFIG['port'], debug=CONFIG['debug'])
