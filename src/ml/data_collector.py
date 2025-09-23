"""
Data Collection Script for ML-Powered Honeypot
Generates and collects training data by simulating various attack patterns
"""

import os
import sys
import time
import random
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import paramiko
import socket
import string
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_collection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AttackSimulator:
    """Simulates various types of attacks to generate training data"""
    
    def __init__(self, config_path: str = "configs/config.yaml"):
        """Initialize the attack simulator with configuration"""
        self.config = self._load_config(config_path)
        self.data_dir = Path(self.config.get('data_dir', 'data/raw'))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Attack patterns and behaviors
        self.scanner_patterns = self._load_attack_patterns('scanner')
        self.amateur_patterns = self._load_attack_patterns('amateur')
        self.advanced_patterns = self._load_attack_patterns('advanced')
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def _load_attack_patterns(self, pattern_type: str) -> List[Dict[str, Any]]:
        """Load attack patterns from configuration"""
        return self.config.get('attack_patterns', {}).get(pattern_type, [])
    
    def _generate_ip(self) -> str:
        """Generate a random IP address"""
        return ".".join(str(random.randint(1, 254)) for _ in range(4))
    
    def _generate_username(self) -> str:
        """Generate a random username"""
        prefixes = ['admin', 'user', 'root', 'test', 'oracle', 'mysql', 'postgres']
        suffixes = ['', '1', '123', '2023', '!@#']
        return random.choice(prefixes) + random.choice(suffixes)
    
    def _generate_password(self, length: int = 8) -> str:
        """Generate a random password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*()"
        return ''.join(random.choice(chars) for _ in range(length))
    
    def _generate_timestamp(self, days_back: int = 30) -> str:
        """Generate a random timestamp within the last N days"""
        now = datetime.now()
        random_days = random.uniform(0, days_back)
        random_seconds = random.uniform(0, 24 * 60 * 60)
        timestamp = now - timedelta(days=random_days, seconds=random_seconds)
        return timestamp.isoformat()
    
    def simulate_scanner_attack(self) -> Dict[str, Any]:
        """Simulate a network scanner attack"""
        pattern = random.choice(self.scanner_patterns)
        return {
            'timestamp': self._generate_timestamp(),
            'source_ip': self._generate_ip(),
            'destination_ip': self._generate_ip(),
            'username': '',
            'password': '',
            'command': pattern.get('command', ''),
            'duration': random.uniform(0.1, 1.0),
            'bytes_sent': random.randint(10, 1000),
            'bytes_received': random.randint(0, 100),
            'threat_level': 'scanner',
            'attack_pattern': pattern.get('name', 'port_scan')
        }
    
    def simulate_amateur_attack(self) -> Dict[str, Any]:
        """Simulate an amateur attacker"""
        pattern = random.choice(self.amateur_patterns)
        return {
            'timestamp': self._generate_timestamp(),
            'source_ip': self._generate_ip(),
            'destination_ip': self._generate_ip(),
            'username': self._generate_username(),
            'password': self._generate_password(),
            'command': pattern.get('command', ''),
            'duration': random.uniform(1.0, 10.0),
            'bytes_sent': random.randint(100, 5000),
            'bytes_received': random.randint(100, 2000),
            'threat_level': 'amateur',
            'attack_pattern': pattern.get('name', 'brute_force')
        }
    
    def simulate_advanced_attack(self) -> Dict[str, Any]:
        """Simulate an advanced persistent threat"""
        pattern = random.choice(self.advanced_patterns)
        return {
            'timestamp': self._generate_timestamp(7),  # More recent attacks
            'source_ip': self._generate_ip(),
            'destination_ip': self._generate_ip(),
            'username': self._generate_username(),
            'password': self._generate_password(12),
            'command': pattern.get('command', ''),
            'duration': random.uniform(10.0, 300.0),
            'bytes_sent': random.randint(1000, 10000),
            'bytes_received': random.randint(500, 5000),
            'threat_level': 'advanced',
            'attack_pattern': pattern.get('name', 'exploit_attempt')
        }
    
    def generate_dataset(self, num_samples: int = 1000) -> pd.DataFrame:
        """
        Generate a dataset of attack simulations
        
        Args:
            num_samples: Total number of samples to generate
            
        Returns:
            DataFrame containing the generated attack data
        """
        logger.info(f"Generating {num_samples} attack samples...")
        
        # Define distribution of attack types
        attack_distribution = {
            'scanner': 0.5,    # 50% scanner attacks
            'amateur': 0.3,    # 30% amateur attacks
            'advanced': 0.2    # 20% advanced attacks
        }
        
        data = []
        for _ in range(num_samples):
            # Select attack type based on distribution
            attack_type = np.random.choice(
                list(attack_distribution.keys()),
                p=list(attack_distribution.values())
            )
            
            # Generate attack data
            if attack_type == 'scanner':
                data.append(self.simulate_scanner_attack())
            elif attack_type == 'amateur':
                data.append(self.simulate_amateur_attack())
            else:  # advanced
                data.append(self.simulate_advanced_attack())
        
        # Convert to DataFrame
        df = pd.DataFrame(data)
        
        # Save to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.data_dir / f"attack_data_{timestamp}.csv"
        df.to_csv(output_file, index=False)
        
        logger.info(f"Generated dataset saved to {output_file}")
        return df

def main():
    """Main function to run the data collection"""
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Generate training data for ML-Powered Honeypot')
    parser.add_argument('--config', type=str, default='configs/config.yaml',
                      help='Path to configuration file')
    parser.add_argument('--samples', type=int, default=1000,
                      help='Number of samples to generate')
    parser.add_argument('--output', type=str,
                      help='Output file path (default: data/raw/attack_data_<timestamp>.csv)')
    
    args = parser.parse_args()
    
    # Initialize and run the data collector
    collector = AttackSimulator(args.config)
    df = collector.generate_dataset(args.samples)
    
    # Save to specified output file if provided
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        print(f"\nDataset saved to: {output_path}")
    
    # Print dataset summary
    print("\nDataset Summary:")
    print(f"Total samples: {len(df)}")
    print("\nThreat level distribution:")
    print(df['threat_level'].value_counts(normalize=True).mul(100))
    print("\nAttack pattern distribution:")
    print(df['attack_pattern'].value_counts(normalize=True).mul(100))

if __name__ == "__main__":
    main()
