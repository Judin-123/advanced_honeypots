"""
Advanced Attack Simulator for Honeypot
Simulates real attacks based on LSNM2024 dataset patterns
"""
import random
import time
import json
import requests
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
import socket
import struct
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('attack_simulator.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AttackSimulator:
    def __init__(self, target_url, attack_intensity=0.3, max_workers=10):
        """
        Initialize the attack simulator
        :param target_url: Base URL of the honeypot (e.g., http://localhost:5000)
        :param attack_intensity: Probability of attack vs normal traffic (0.0 to 1.0)
        :param max_workers: Maximum number of concurrent attack threads
        """
        self.target_url = target_url
        self.attack_intensity = attack_intensity
        self.max_workers = max_workers
        self.session = requests.Session()
        self.user_agents = self._load_user_agents()
        self.attack_patterns = self._load_attack_patterns()
        self.normal_patterns = self._load_normal_patterns()
        self.attacker_ips = self._generate_attacker_ips(50)  # Generate 50 attacker IPs
        
        # Track attack metrics
        self.metrics = {
            'total_requests': 0,
            'attack_requests': 0,
            'normal_requests': 0,
            'successful_attacks': 0,
            'blocked_attacks': 0,
            'attack_types': {},
            'start_time': datetime.now().isoformat()
        }
    
    def _load_user_agents(self):
        """Load a list of user agents for requests"""
        return [
            # Browsers
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            # Security tools
            'nmap/7.93',
            'sqlmap/1.6.12.10#dev',
            'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)',
            'OWASP ZAP/2.12.0',
            'Nikto/2.1.6',
            'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0 (Burp Suite)',
            'w3af.org/2.3.0',
            # API clients
            'python-requests/2.31.0',
            'curl/8.1.2',
            'PostmanRuntime/7.32.3',
            'Go-http-client/1.1'
        ]
    
    def _load_attack_patterns(self):
        """Load attack patterns based on LSNM2024 dataset"""
        return [
            # Web Application Attacks
            {
                'type': 'SQL Injection',
                'method': 'GET',
                'path': '/search',
                'params': {'q': "1' OR '1'='1'--"},
                'headers': {},
                'severity': 'High',
                'description': 'Basic SQL Injection attempt'
            },
            {
                'type': 'XSS',
                'method': 'GET',
                'path': '/comment',
                'params': {'text': '<script>alert(1)</script>'},
                'headers': {},
                'severity': 'Medium',
                'description': 'Reflected XSS attempt'
            },
            {
                'type': 'Command Injection',
                'method': 'GET',
                'path': '/ping',
                'params': {'ip': '127.0.0.1; cat /etc/passwd'},
                'headers': {},
                'severity': 'Critical',
                'description': 'Command injection in ping parameter'
            },
            # Network Scans
            {
                'type': 'Port Scan',
                'method': 'GET',
                'path': '/',
                'params': {},
                'headers': {'X-Scanner': 'nmap'},
                'severity': 'Low',
                'description': 'Port scanning activity'
            },
            # Authentication Attacks
            {
                'type': 'Brute Force',
                'method': 'POST',
                'path': '/login',
                'data': {'username': 'admin', 'password': 'admin123'},
                'headers': {},
                'severity': 'High',
                'description': 'Default credential attempt'
            },
            # Directory Traversal
            {
                'type': 'LFI',
                'method': 'GET',
                'path': '/../../../../etc/passwd',
                'params': {},
                'headers': {},
                'severity': 'High',
                'description': 'Local File Inclusion attempt'
            },
            # Server-Side Attacks
            {
                'type': 'SSRF',
                'method': 'GET',
                'path': '/fetch',
                'params': {'url': 'http://169.254.169.254/latest/meta-data/'},
                'headers': {},
                'severity': 'Critical',
                'description': 'Server-Side Request Forgery attempt'
            },
            # API Abuse
            {
                'type': 'API Abuse',
                'method': 'GET',
                'path': '/api/v1/users',
                'params': {'limit': '1000', 'offset': '0'},
                'headers': {'Authorization': 'Bearer invalid_token'},
                'severity': 'Medium',
                'description': 'Excessive data access attempt'
            },
            # XML External Entity
            {
                'type': 'XXE',
                'method': 'POST',
                'path': '/upload',
                'data': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                'headers': {'Content-Type': 'application/xml'},
                'severity': 'Critical',
                'description': 'XML External Entity injection attempt'
            },
            # Server-Side Template Injection
            {
                'type': 'SSTI',
                'method': 'GET',
                'path': '/render',
                'params': {'template': '{{7*7}}'},
                'headers': {},
                'severity': 'High',
                'description': 'Server-Side Template Injection attempt'
            }
        ]
    
    def _load_normal_patterns(self):
        """Load normal traffic patterns"""
        return [
            {'method': 'GET', 'path': '/', 'params': {}},
            {'method': 'GET', 'path': '/about', 'params': {}},
            {'method': 'GET', 'path': '/contact', 'params': {}},
            {'method': 'GET', 'path': '/products', 'params': {}},
            {'method': 'GET', 'path': '/blog', 'params': {}},
            {'method': 'GET', 'path': '/login', 'params': {}},
            {'method': 'GET', 'path': '/register', 'params': {}},
            {'method': 'POST', 'path': '/search', 'data': {'q': 'test'}},
            {'method': 'GET', 'path': '/api/v1/products', 'params': {'limit': '10'}}
        ]
    
    def _generate_attacker_ips(self, count):
        """Generate a list of attacker IP addresses"""
        # Generate IPs from different subnets for realism
        networks = [
            '5.188.0.0/16',    # Known scanner range
            '45.227.253.0/24',  # Known malicious IP range
            '185.142.236.0/24', # Another scanner range
            '192.168.0.0/16',   # Internal network
            '10.0.0.0/8'        # Another internal range
        ]
        
        ips = []
        for net in networks:
            network = ipaddress.IPv4Network(net, strict=False)
            for _ in range(count // len(networks)):
                ips.append(str(network[random.randint(0, network.num_addresses - 1)]))
        
        return ips
    
    def _send_request(self, method, path, params=None, data=None, headers=None, is_attack=False, attack_type=None):
        """Send an HTTP request to the target"""
        url = urljoin(self.target_url, path)
        headers = headers or {}
        
        # Add random user agent if not specified
        if 'User-Agent' not in headers:
            headers['User-Agent'] = random.choice(self.user_agents)
        
        # Add X-Forwarded-For header to simulate different IPs
        if 'X-Forwarded-For' not in headers:
            headers['X-Forwarded-For'] = random.choice(self.attacker_ips)
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, headers=headers, timeout=5)
            elif method.upper() == 'POST':
                if isinstance(data, dict):
                    response = self.session.post(url, json=data, headers=headers, timeout=5)
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                    response = self.session.post(url, data=data, headers=headers, timeout=5)
            else:
                logger.warning(f"Unsupported method: {method}")
                return False
            
            # Log the result
            self.metrics['total_requests'] += 1
            if is_attack:
                self.metrics['attack_requests'] += 1
                if attack_type not in self.metrics['attack_types']:
                    self.metrics['attack_types'][attack_type] = 0
                self.metrics['attack_types'][attack_type] += 1
                
                if response.status_code < 400:  # Consider it successful if not a client/server error
                    self.metrics['successful_attacks'] += 1
                    logger.info(f"✅ Attack successful: {attack_type} - {response.status_code}")
                else:
                    self.metrics['blocked_attacks'] += 1
                    logger.warning(f"❌ Attack blocked: {attack_type} - {response.status_code}")
            else:
                self.metrics['normal_requests'] += 1
                logger.debug(f"Normal request to {path} - {response.status_code}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending request: {e}")
            return False
    
    def generate_normal_traffic(self, count=1):
        """Generate normal traffic patterns"""
        for _ in range(count):
            pattern = random.choice(self.normal_patterns)
            self._send_request(
                method=pattern['method'],
                path=pattern['path'],
                params=pattern.get('params'),
                data=pattern.get('data'),
                headers=pattern.get('headers', {})
            )
            # Random delay between normal requests
            time.sleep(random.uniform(0.1, 1.0))
    
    def launch_attack(self, attack_pattern):
        """Launch a specific attack pattern"""
        return self._send_request(
            method=attack_pattern['method'],
            path=attack_pattern['path'],
            params=attack_pattern.get('params'),
            data=attack_pattern.get('data'),
            headers=attack_pattern.get('headers', {}),
            is_attack=True,
            attack_type=attack_pattern['type']
        )
    
    def random_attack(self):
        """Launch a random attack"""
        attack = random.choice(self.attack_patterns)
        return self.launch_attack(attack)
    
    def run_simulation(self, duration_minutes=10):
        """Run the attack simulation for a specified duration"""
        logger.info(f"🚀 Starting attack simulation for {duration_minutes} minutes...")
        logger.info(f"Target: {self.target_url}")
        logger.info(f"Attack intensity: {self.attack_intensity*100}%")
        
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        request_count = 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            while datetime.now() < end_time:
                # Decide if this should be an attack or normal traffic
                if random.random() < self.attack_intensity:
                    # Launch attack
                    attack = random.choice(self.attack_patterns)
                    futures.append(executor.submit(self.launch_attack, attack))
                    logger.debug(f"Launched attack: {attack['type']}")
                else:
                    # Generate normal traffic
                    pattern = random.choice(self.normal_patterns)
                    futures.append(executor.submit(
                        self._send_request,
                        method=pattern['method'],
                        path=pattern['path'],
                        params=pattern.get('params'),
                        data=pattern.get('data'),
                        headers=pattern.get('headers', {})
                    ))
                
                request_count += 1
                
                # Random delay between requests
                time.sleep(random.uniform(0.05, 0.5))
                
                # Log progress
                if request_count % 10 == 0:
                    logger.info(f"Sent {request_count} requests ({self.metrics['attack_requests']} attacks)")
        
        # Wait for all futures to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error in request: {e}")
        
        self._generate_report()
    
    def _generate_report(self):
        """Generate a summary report of the simulation"""
        duration = datetime.now() - datetime.fromisoformat(self.metrics['start_time'])
        
        report = """
=== Attack Simulation Report ===
Summary:
  - Total Duration: {duration}
  - Total Requests: {total_requests}
  - Normal Requests: {normal_requests}
  - Attack Requests: {attack_requests}
  - Successful Attacks: {successful_attacks}
  - Blocked Attacks: {blocked_requests}
  - Attack Success Rate: {success_rate:.1f}%

Attack Types:
{attack_types}
"""
        # Calculate success rate (avoid division by zero)
        total_attacks = self.metrics['attack_requests']
        success_rate = (self.metrics['successful_attacks'] / total_attacks * 100) if total_attacks > 0 else 0
        
        # Format attack types
        attack_types = '\n'.join([f"  - {k}: {v}" for k, v in self.metrics['attack_types'].items()])
        
        report = report.format(
            duration=str(duration).split('.')[0],  # Remove microseconds
            total_requests=self.metrics['total_requests'],
            normal_requests=self.metrics['normal_requests'],
            attack_requests=self.metrics['attack_requests'],
            successful_attacks=self.metrics['successful_attacks'],
            blocked_requests=self.metrics['blocked_attacks'],
            success_rate=success_rate,
            attack_types=attack_types or '  No attacks launched'
        )
        
        logger.info("\n" + "="*50)
        logger.info(report)
        logger.info("="*50)
        
        # Save report to file
        with open('attack_simulation_report.txt', 'w') as f:
            f.write(report)
        
        logger.info("Report saved to attack_simulation_report.txt")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Honeypot Attack Simulator')
    parser.add_argument('--target', type=str, default='http://localhost:5000',
                       help='Target URL (default: http://localhost:5000)')
    parser.add_argument('--duration', type=int, default=10,
                       help='Duration of simulation in minutes (default: 10)')
    parser.add_argument('--intensity', type=float, default=0.3,
                       help='Attack intensity (0.0 to 1.0, default: 0.3)')
    parser.add_argument('--workers', type=int, default=10,
                       help='Maximum number of concurrent workers (default: 10)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    simulator = AttackSimulator(
        target_url=args.target,
        attack_intensity=args.intensity,
        max_workers=args.workers
    )
    
    try:
        simulator.run_simulation(duration_minutes=args.duration)
    except KeyboardInterrupt:
        logger.info("\nSimulation interrupted. Generating report...")
        simulator._generate_report()


if __name__ == '__main__':
    main()
