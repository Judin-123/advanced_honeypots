"""
Adaptive Honeypot System - Responds intelligently to hacker behavior
Changes tactics based on attack patterns and ML analysis
"""
import os
import json
import time
import random
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
import joblib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AdaptiveHoneypotSystem:
    """Intelligent honeypot that adapts to hacker behavior"""
    
    def __init__(self):
        # Load ML models for threat analysis
        self.load_models()
        
        # Adaptive profiles
        self.profiles = {
            'minimal': {
                'services': ['ssh'],
                'response_delay': 0.1,
                'fake_files': 10,
                'deception_level': 1
            },
            'standard': {
                'services': ['ssh', 'http', 'ftp'],
                'response_delay': 0.5,
                'fake_files': 50,
                'deception_level': 3
            },
            'aggressive': {
                'services': ['ssh', 'http', 'ftp', 'telnet', 'smtp'],
                'response_delay': 1.0,
                'fake_files': 200,
                'deception_level': 5
            },
            'deceptive': {
                'services': ['ssh', 'http', 'ftp', 'telnet', 'smtp', 'mysql', 'rdp'],
                'response_delay': 2.0,
                'fake_files': 500,
                'deception_level': 8
            }
        }
        
        # Current state
        self.current_profile = 'standard'
        self.attacker_patterns = defaultdict(list)
        self.blocked_ips = set()
        self.session_history = deque(maxlen=1000)
        
        # Adaptive thresholds
        self.threat_threshold = 0.7
        self.adaptation_interval = 300  # 5 minutes
        
        # Start adaptive monitoring
        self.start_adaptive_monitoring()
    
    def load_models(self):
        """Load ML models for threat analysis"""
        try:
            self.models = {}
            if os.path.exists('trained_models/xgboost_model.pkl'):
                self.models['xgboost'] = joblib.load('trained_models/xgboost_model.pkl')
            if os.path.exists('trained_models/scaler.pkl'):
                self.scaler = joblib.load('trained_models/scaler.pkl')
            if os.path.exists('trained_models/feature_columns.pkl'):
                self.feature_columns = joblib.load('trained_models/feature_columns.pkl')
            logger.info(f"✅ Loaded {len(self.models)} ML models for adaptation")
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            self.models = {}
    
    def start_adaptive_monitoring(self):
        """Start the adaptive monitoring system"""
        def monitor():
            logger.info("🧠 Starting adaptive honeypot monitoring...")
            while True:
                try:
                    # Analyze recent attack patterns
                    self.analyze_attack_patterns()
                    
                    # Adapt honeypot behavior
                    self.adapt_honeypot_behavior()
                    
                    # Update deception tactics
                    self.update_deception_tactics()
                    
                    time.sleep(self.adaptation_interval)
                    
                except Exception as e:
                    logger.error(f"Adaptive monitoring error: {e}")
                    time.sleep(60)
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
    
    def analyze_attack_patterns(self):
        """Analyze recent attack patterns to determine adaptation strategy"""
        logger.info("🔍 Analyzing attack patterns...")
        
        # Get recent sessions (last hour)
        recent_time = datetime.now() - timedelta(hours=1)
        recent_attacks = [s for s in self.session_history 
                         if s.get('timestamp', datetime.min) > recent_time]
        
        if not recent_attacks:
            logger.info("No recent attacks - maintaining current profile")
            return
        
        # Analyze attack characteristics
        attack_analysis = {
            'total_attacks': len(recent_attacks),
            'unique_ips': len(set(a.get('source_ip') for a in recent_attacks)),
            'protocols': defaultdict(int),
            'threat_levels': defaultdict(int),
            'attack_types': defaultdict(int)
        }
        
        for attack in recent_attacks:
            attack_analysis['protocols'][attack.get('protocol', 'unknown')] += 1
            attack_analysis['threat_levels'][attack.get('severity', 'low')] += 1
            attack_analysis['attack_types'][attack.get('threat_type', 'unknown')] += 1
        
        # Determine adaptation strategy
        self.determine_adaptation_strategy(attack_analysis)
    
    def determine_adaptation_strategy(self, analysis):
        """Determine how to adapt based on attack analysis"""
        total_attacks = analysis['total_attacks']
        unique_ips = analysis['unique_ips']
        
        logger.info(f"📊 Attack Analysis: {total_attacks} attacks from {unique_ips} IPs")
        
        # Adaptation logic
        if total_attacks > 50:
            # Heavy attack - go aggressive
            new_profile = 'aggressive'
            reason = f"Heavy attack volume ({total_attacks} attacks)"
        elif unique_ips > 10:
            # Distributed attack - be deceptive
            new_profile = 'deceptive' 
            reason = f"Distributed attack ({unique_ips} unique IPs)"
        elif analysis['threat_levels']['high'] > 5:
            # High-severity threats - be aggressive
            new_profile = 'aggressive'
            reason = f"High-severity threats detected"
        elif total_attacks < 5:
            # Low activity - minimal profile
            new_profile = 'minimal'
            reason = "Low attack activity"
        else:
            # Normal activity - standard profile
            new_profile = 'standard'
            reason = "Normal attack patterns"
        
        if new_profile != self.current_profile:
            logger.info(f"🔄 ADAPTING: {self.current_profile} → {new_profile} ({reason})")
            self.switch_profile(new_profile)
        else:
            logger.info(f"✅ Maintaining {self.current_profile} profile")
    
    def switch_profile(self, new_profile):
        """Switch to a new adaptive profile"""
        old_profile = self.current_profile
        self.current_profile = new_profile
        profile_config = self.profiles[new_profile]
        
        logger.info(f"🎭 Switching from {old_profile} to {new_profile} profile")
        logger.info(f"   Services: {profile_config['services']}")
        logger.info(f"   Response delay: {profile_config['response_delay']}s")
        logger.info(f"   Deception level: {profile_config['deception_level']}/10")
        
        # Apply profile changes
        self.apply_profile_changes(profile_config)
        
        # Log the adaptation
        self.log_adaptation(old_profile, new_profile)
    
    def apply_profile_changes(self, config):
        """Apply the configuration changes for the new profile"""
        try:
            # Start/stop services based on profile
            self.manage_services(config['services'])
            
            # Update response characteristics
            self.update_response_behavior(config)
            
            # Generate appropriate fake content
            self.generate_fake_content(config)
            
        except Exception as e:
            logger.error(f"Error applying profile changes: {e}")
    
    def manage_services(self, required_services):
        """Start or stop honeypot services based on profile"""
        logger.info(f"🔧 Managing services: {required_services}")
        
        # This would integrate with actual honeypot services
        # For now, we'll simulate service management
        
        service_ports = {
            'ssh': 22,
            'http': 80,
            'https': 443,
            'ftp': 21,
            'telnet': 23,
            'smtp': 25,
            'mysql': 3306,
            'rdp': 3389
        }
        
        for service in required_services:
            port = service_ports.get(service, 0)
            logger.info(f"   ✅ Starting {service} honeypot on port {port}")
            # Here you would start actual honeypot services
            # subprocess.run(['python', f'honeypots/{service}_honeypot.py'])
    
    def update_response_behavior(self, config):
        """Update how the honeypot responds to interactions"""
        delay = config['response_delay']
        deception = config['deception_level']
        
        logger.info(f"🎯 Updating response behavior:")
        logger.info(f"   Response delay: {delay}s")
        logger.info(f"   Deception level: {deception}/10")
        
        # Configure response characteristics
        response_config = {
            'delay': delay,
            'fake_errors': deception > 3,
            'misleading_banners': deception > 5,
            'fake_vulnerabilities': deception > 7
        }
        
        # Save config for honeypot services to use
        with open('honeypot_config.json', 'w') as f:
            json.dump(response_config, f, indent=2)
    
    def generate_fake_content(self, config):
        """Generate fake files and content based on deception level"""
        fake_files = config['fake_files']
        deception = config['deception_level']
        
        logger.info(f"📁 Generating {fake_files} fake files (deception level {deception})")
        
        # Create fake file structure
        fake_content = self.create_fake_filesystem(fake_files, deception)
        
        # Save fake content manifest
        with open('fake_content.json', 'w') as f:
            json.dump(fake_content, f, indent=2)
    
    def create_fake_filesystem(self, num_files, deception_level):
        """Create a fake filesystem to deceive attackers"""
        fake_files = {}
        
        # Basic files (always present)
        basic_files = [
            '/etc/passwd', '/etc/shadow', '/home/admin/.ssh/id_rsa',
            '/var/log/auth.log', '/root/.bash_history'
        ]
        
        # Deceptive files based on level
        if deception_level > 3:
            basic_files.extend([
                '/home/admin/passwords.txt', '/var/www/config.php',
                '/root/backup.sql', '/etc/mysql/my.cnf'
            ])
        
        if deception_level > 6:
            basic_files.extend([
                '/home/admin/bitcoin_wallet.dat', '/root/company_secrets.txt',
                '/var/backups/database_dump.sql', '/etc/ssl/private/server.key'
            ])
        
        # Generate fake content for each file
        for i, filepath in enumerate(basic_files[:num_files]):
            fake_files[filepath] = {
                'size': random.randint(100, 10000),
                'modified': datetime.now().isoformat(),
                'content_type': self.get_fake_content_type(filepath),
                'honeypot_trap': True
            }
        
        return fake_files
    
    def get_fake_content_type(self, filepath):
        """Determine fake content type based on file path"""
        if 'passwd' in filepath:
            return 'user_accounts'
        elif 'ssh' in filepath:
            return 'ssh_keys'
        elif 'password' in filepath:
            return 'credentials'
        elif '.sql' in filepath:
            return 'database'
        else:
            return 'system_file'
    
    def update_deception_tactics(self):
        """Update deception tactics based on current threats"""
        logger.info("🎭 Updating deception tactics...")
        
        # Analyze what attackers are looking for
        recent_commands = self.get_recent_attacker_commands()
        
        # Adapt fake content based on attacker interests
        if any('mysql' in cmd for cmd in recent_commands):
            self.create_fake_database_content()
        
        if any('ssh' in cmd or 'key' in cmd for cmd in recent_commands):
            self.create_fake_ssh_content()
        
        if any('passwd' in cmd or 'user' in cmd for cmd in recent_commands):
            self.create_fake_user_content()
    
    def get_recent_attacker_commands(self):
        """Get commands that attackers have been trying"""
        # This would parse actual honeypot logs for commands
        # For now, return some example commands
        return [
            'cat /etc/passwd',
            'ls -la /root',
            'mysql -u root -p',
            'find / -name "*.key"',
            'ps aux'
        ]
    
    def create_fake_database_content(self):
        """Create fake database content to trap attackers"""
        logger.info("🗄️ Creating fake database content...")
        
        fake_db = {
            'users': [
                {'id': 1, 'username': 'admin', 'password_hash': 'fake_hash_123'},
                {'id': 2, 'username': 'root', 'password_hash': 'fake_hash_456'}
            ],
            'config': {
                'db_host': '192.168.1.100',
                'db_user': 'honeypot_trap',
                'db_pass': 'this_is_fake'
            }
        }
        
        with open('fake_database.json', 'w') as f:
            json.dump(fake_db, f, indent=2)
    
    def create_fake_ssh_content(self):
        """Create fake SSH keys and config"""
        logger.info("🔑 Creating fake SSH content...")
        
        fake_ssh = {
            'private_key': '-----BEGIN FAKE RSA PRIVATE KEY-----\nThis is a honeypot trap\n-----END FAKE RSA PRIVATE KEY-----',
            'authorized_keys': 'ssh-rsa FAKE_KEY_DATA honeypot@trap',
            'known_hosts': '192.168.1.1 ssh-rsa FAKE_HOST_KEY'
        }
        
        with open('fake_ssh.json', 'w') as f:
            json.dump(fake_ssh, f, indent=2)
    
    def create_fake_user_content(self):
        """Create fake user accounts and passwords"""
        logger.info("👥 Creating fake user content...")
        
        fake_users = {
            'passwd_entries': [
                'root:x:0:0:root:/root:/bin/bash',
                'admin:x:1000:1000:Admin User:/home/admin:/bin/bash',
                'honeypot:x:1001:1001:Honeypot Trap:/home/honeypot:/bin/bash'
            ],
            'shadow_entries': [
                'root:$6$fake_salt$fake_hash:18000:0:99999:7:::',
                'admin:$6$fake_salt$fake_hash:18000:0:99999:7:::'
            ]
        }
        
        with open('fake_users.json', 'w') as f:
            json.dump(fake_users, f, indent=2)
    
    def log_adaptation(self, old_profile, new_profile):
        """Log the adaptation for analysis"""
        adaptation_log = {
            'timestamp': datetime.now().isoformat(),
            'old_profile': old_profile,
            'new_profile': new_profile,
            'reason': 'Adaptive response to attack patterns',
            'attack_count': len(self.session_history)
        }
        
        # Append to adaptation log
        log_file = 'adaptation_log.json'
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        logs.append(adaptation_log)
        
        with open(log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def process_new_session(self, session_data):
        """Process a new session and trigger adaptation if needed"""
        # Add to session history
        session_data['timestamp'] = datetime.now()
        self.session_history.append(session_data)
        
        # Analyze threat level using ML
        if self.models:
            threat_score = self.analyze_threat_ml(session_data)
            session_data['ml_threat_score'] = threat_score
            
            # Immediate response for high-threat sessions
            if threat_score > 0.9:
                self.immediate_threat_response(session_data)
        
        # Update attacker patterns
        source_ip = session_data.get('source_ip')
        if source_ip:
            self.attacker_patterns[source_ip].append(session_data)
    
    def analyze_threat_ml(self, session_data):
        """Use ML models to analyze threat level"""
        try:
            # Extract features (simplified)
            features = [
                len(session_data.get('commands', [])),
                1 if 'failed' in str(session_data) else 0,
                len(session_data.get('source_ip', '')),
                # Add more features based on your model
            ]
            
            # Pad to match training features
            while len(features) < len(self.feature_columns):
                features.append(0)
            
            # Scale and predict
            if self.scaler:
                features_scaled = self.scaler.transform([features[:len(self.feature_columns)]])
                if 'xgboost' in self.models:
                    prediction = self.models['xgboost'].predict_proba(features_scaled)[0]
                    return float(prediction[1]) if len(prediction) > 1 else 0.5
            
            return 0.5
            
        except Exception as e:
            logger.error(f"ML analysis error: {e}")
            return 0.5
    
    def immediate_threat_response(self, session_data):
        """Immediate response to high-threat sessions"""
        source_ip = session_data.get('source_ip')
        logger.warning(f"🚨 HIGH THREAT detected from {source_ip}")
        
        # Block IP immediately
        self.block_ip(source_ip)
        
        # Switch to aggressive profile if not already
        if self.current_profile != 'aggressive':
            logger.info("🔥 Switching to AGGRESSIVE profile due to high threat")
            self.switch_profile('aggressive')
    
    def block_ip(self, ip_address):
        """Block an IP address using firewall"""
        if ip_address not in self.blocked_ips:
            try:
                # Windows Firewall command
                rule_name = f"HoneypotBlock_{ip_address.replace('.', '_')}"
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
                
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    self.blocked_ips.add(ip_address)
                    logger.info(f"🚫 BLOCKED IP: {ip_address}")
                else:
                    logger.error(f"Failed to block {ip_address}: {result.stderr}")
                    
            except Exception as e:
                logger.error(f"Error blocking IP {ip_address}: {e}")
    
    def get_status(self):
        """Get current adaptive honeypot status"""
        return {
            'current_profile': self.current_profile,
            'profile_config': self.profiles[self.current_profile],
            'total_sessions': len(self.session_history),
            'blocked_ips': len(self.blocked_ips),
            'unique_attackers': len(self.attacker_patterns),
            'models_loaded': len(self.models)
        }

def main():
    """Run the adaptive honeypot system"""
    print("=" * 80)
    print("🧠 ADAPTIVE HONEYPOT SYSTEM")
    print("=" * 80)
    print()
    print("🎯 Adaptive Features:")
    print("   • ML-powered threat analysis")
    print("   • Dynamic profile switching")
    print("   • Intelligent deception tactics")
    print("   • Real-time IP blocking")
    print("   • Behavioral adaptation")
    print()
    
    system = AdaptiveHoneypotSystem()
    
    print("✅ Adaptive honeypot system started")
    print("🔄 Monitoring and adapting to attack patterns...")
    print()
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            status = system.get_status()
            print(f"📊 Status: {status['current_profile']} profile | "
                  f"{status['total_sessions']} sessions | "
                  f"{status['blocked_ips']} IPs blocked")
            time.sleep(30)
            
    except KeyboardInterrupt:
        print("\n👋 Adaptive honeypot stopped")

if __name__ == '__main__':
    main()