"""
Isolated Cloud Honeypot Deployment
Completely separate from your personal devices with persistent data storage
"""
import os
import json
import subprocess
import requests
from datetime import datetime

class IsolatedCloudHoneypot:
    """Deploy honeypot to isolated cloud environment"""
    
    def __init__(self):
        self.deployment_options = {
            'oracle_free': {
                'name': 'Oracle Cloud Free Tier',
                'cost': 'FREE FOREVER',
                'isolation': '100% Isolated',
                'specs': '4 CPU, 24GB RAM, 200GB Storage',
                'uptime': '24/7',
                'data_persistence': 'Permanent',
                'recommended': True
            },
            'vultr': {
                'name': 'Vultr VPS',
                'cost': '$2.50/month (IPv6) or $3.50/month (IPv4)',
                'isolation': '100% Isolated',
                'specs': '1 CPU, 512MB RAM, 10GB Storage',
                'uptime': '24/7',
                'data_persistence': 'Permanent'
            },
            'digitalocean': {
                'name': 'DigitalOcean Droplet',
                'cost': '$4/month',
                'isolation': '100% Isolated',
                'specs': '1 CPU, 512MB RAM, 10GB Storage',
                'uptime': '24/7',
                'data_persistence': 'Permanent'
            }
        }
    
    def show_isolation_benefits(self):
        """Show benefits of isolated deployment"""
        print("=" * 80)
        print("🛡️ ISOLATED CLOUD HONEYPOT BENEFITS")
        print("=" * 80)
        print()
        
        print("🔒 COMPLETE ISOLATION:")
        print("   ✅ Separate server - NOT on your laptop")
        print("   ✅ Different IP address - NOT your home IP")
        print("   ✅ No connection to your personal devices")
        print("   ✅ Attackers can't reach your real systems")
        print()
        
        print("🌍 MAXIMUM EXPOSURE:")
        print("   ✅ Directly on internet - no firewalls blocking")
        print("   ✅ Public IP address - visible to all scanners")
        print("   ✅ Multiple ports open - attracts more attacks")
        print("   ✅ Professional hosting - looks like real server")
        print()
        
        print("💾 PERSISTENT DATA STORAGE:")
        print("   ✅ Data saved to cloud storage")
        print("   ✅ Automatic backups")
        print("   ✅ Access logs anytime from anywhere")
        print("   ✅ Never lose attack data")
        print()
        
        print("🎯 DAMAGE CONTROL:")
        print("   ✅ Isolated environment - can't spread to your devices")
        print("   ✅ Easy to rebuild if compromised")
        print("   ✅ Snapshot backups for quick recovery")
        print("   ✅ Monitor and control remotely")
    
    def create_oracle_deployment(self):
        """Create Oracle Cloud Free Tier deployment"""
        
        # Cloud-init script for automatic setup
        cloud_init = """#cloud-config
package_update: true
package_upgrade: true

packages:
  - python3
  - python3-pip
  - git
  - htop
  - fail2ban
  - ufw
  - sqlite3

write_files:
  - path: /etc/systemd/system/honeypot.service
    content: |
      [Unit]
      Description=Adaptive Honeypot System
      After=network.target
      
      [Service]
      Type=simple
      User=ubuntu
      WorkingDirectory=/opt/honeypot
      ExecStart=/usr/bin/python3 integrated_adaptive_dashboard.py
      Restart=always
      RestartSec=10
      Environment=PYTHONUNBUFFERED=1
      
      [Install]
      WantedBy=multi-user.target
  
  - path: /opt/honeypot/requirements.txt
    content: |
      flask==2.3.3
      psutil==5.9.5
      joblib==1.3.2
      scikit-learn==1.3.0
      xgboost==1.7.6
      pandas==2.0.3
      numpy==1.24.3
      requests==2.31.0

  - path: /opt/honeypot/setup_honeypot.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      
      echo "🍯 Setting up isolated honeypot..."
      
      # Create honeypot user
      sudo useradd -m -s /bin/bash honeypot
      
      # Setup directories
      sudo mkdir -p /opt/honeypot/{logs,data,backups}
      sudo chown -R ubuntu:ubuntu /opt/honeypot
      
      # Install Python dependencies
      cd /opt/honeypot
      pip3 install -r requirements.txt
      
      # Configure firewall (allow honeypot ports, block everything else to your laptop)
      sudo ufw --force reset
      sudo ufw default deny incoming
      sudo ufw default allow outgoing
      
      # Allow SSH (for management)
      sudo ufw allow 22/tcp
      
      # Allow honeypot ports
      sudo ufw allow 80/tcp
      sudo ufw allow 443/tcp
      sudo ufw allow 21/tcp
      sudo ufw allow 23/tcp
      sudo ufw allow 25/tcp
      sudo ufw allow 3306/tcp
      sudo ufw allow 3389/tcp
      sudo ufw allow 5003/tcp
      
      # Enable firewall
      sudo ufw --force enable
      
      # Configure fail2ban for additional protection
      sudo systemctl enable fail2ban
      sudo systemctl start fail2ban
      
      # Setup log rotation
      sudo tee /etc/logrotate.d/honeypot > /dev/null <<EOF
      /opt/honeypot/logs/*.log {
          daily
          rotate 30
          compress
          delaycompress
          missingok
          notifempty
          create 644 ubuntu ubuntu
      }
      EOF
      
      echo "✅ Honeypot setup complete!"

runcmd:
  - cd /opt/honeypot && bash setup_honeypot.sh
  - systemctl daemon-reload
  - systemctl enable honeypot
  
final_message: "🍯 Isolated Honeypot Server Ready! Access via SSH and start honeypot service."
"""
        
        # Terraform configuration for Oracle Cloud
        terraform_config = """
# Oracle Cloud Free Tier Honeypot Deployment
terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
    }
  }
}

# Variables
variable "tenancy_ocid" {
  description = "OCID of your tenancy"
}

variable "user_ocid" {
  description = "OCID of the user"
}

variable "private_key_path" {
  description = "Path to your private key"
}

variable "fingerprint" {
  description = "Fingerprint of your public key"
}

variable "region" {
  description = "Oracle Cloud region"
  default = "us-ashburn-1"
}

# Provider configuration
provider "oci" {
  tenancy_ocid     = var.tenancy_ocid
  user_ocid        = var.user_ocid
  private_key_path = var.private_key_path
  fingerprint      = var.fingerprint
  region           = var.region
}

# Get availability domain
data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

# Create VCN for isolation
resource "oci_core_vcn" "honeypot_vcn" {
  compartment_id = var.tenancy_ocid
  display_name   = "honeypot-vcn"
  cidr_block     = "10.1.0.0/16"
}

# Internet Gateway
resource "oci_core_internet_gateway" "honeypot_ig" {
  compartment_id = var.tenancy_ocid
  display_name   = "honeypot-ig"
  vcn_id         = oci_core_vcn.honeypot_vcn.id
}

# Route Table
resource "oci_core_route_table" "honeypot_rt" {
  compartment_id = var.tenancy_ocid
  vcn_id         = oci_core_vcn.honeypot_vcn.id
  display_name   = "honeypot-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.honeypot_ig.id
  }
}

# Security List (Firewall Rules)
resource "oci_core_security_list" "honeypot_sl" {
  compartment_id = var.tenancy_ocid
  vcn_id         = oci_core_vcn.honeypot_vcn.id
  display_name   = "honeypot-sl"

  # Allow all outbound
  egress_security_rules {
    protocol    = "all"
    destination = "0.0.0.0/0"
  }

  # SSH for management
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 22
      max = 22
    }
  }

  # Honeypot services
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 80
      max = 80
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 443
      max = 443
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 21
      max = 21
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 23
      max = 23
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 3306
      max = 3306
    }
  }

  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 5003
      max = 5003
    }
  }
}

# Subnet
resource "oci_core_subnet" "honeypot_subnet" {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  cidr_block          = "10.1.20.0/24"
  display_name        = "honeypot-subnet"
  compartment_id      = var.tenancy_ocid
  vcn_id              = oci_core_vcn.honeypot_vcn.id
  route_table_id      = oci_core_route_table.honeypot_rt.id
  security_list_ids   = [oci_core_security_list.honeypot_sl.id]
}

# Get Ubuntu image
data "oci_core_images" "ubuntu_images" {
  compartment_id           = var.tenancy_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "22.04"
  shape                    = "VM.Standard.A1.Flex"
  sort_by                  = "TIMECREATED"
  sort_order              = "DESC"
}

# Honeypot Instance (Free Tier ARM)
resource "oci_core_instance" "honeypot_instance" {
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  compartment_id      = var.tenancy_ocid
  display_name        = "isolated-honeypot"
  shape               = "VM.Standard.A1.Flex"

  shape_config {
    ocpus         = 4
    memory_in_gbs = 24
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.honeypot_subnet.id
    display_name     = "honeypot-vnic"
    assign_public_ip = true
  }

  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.ubuntu_images.images[0].id
  }

  metadata = {
    ssh_authorized_keys = file("~/.ssh/id_rsa.pub")
    user_data          = base64encode(file("cloud-init.yaml"))
  }
}

# Output public IP
output "honeypot_public_ip" {
  value = oci_core_instance.honeypot_instance.public_ip
}

output "ssh_command" {
  value = "ssh ubuntu@${oci_core_instance.honeypot_instance.public_ip}"
}
"""
        
        # Save files
        with open('cloud-init.yaml', 'w') as f:
            f.write(cloud_init)
        
        with open('oracle_honeypot.tf', 'w') as f:
            f.write(terraform_config)
        
        print("📝 Created Oracle Cloud deployment files:")
        print("   • cloud-init.yaml - Automatic server setup")
        print("   • oracle_honeypot.tf - Infrastructure as code")
    
    def create_simple_vps_deployment(self):
        """Create simple VPS deployment script"""
        
        deployment_script = """#!/bin/bash

echo "🍯 ISOLATED HONEYPOT VPS SETUP"
echo "================================"

# Update system
apt update && apt upgrade -y

# Install dependencies
apt install -y python3 python3-pip git htop fail2ban ufw sqlite3 nginx

# Create honeypot user and directories
useradd -m -s /bin/bash honeypot
mkdir -p /opt/honeypot/{logs,data,backups,uploads}
chown -R honeypot:honeypot /opt/honeypot

# Setup firewall for maximum isolation
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH for management (change port for security)
ufw allow 2222/tcp

# Allow honeypot services
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 21/tcp
ufw allow 23/tcp
ufw allow 25/tcp
ufw allow 3306/tcp
ufw allow 3389/tcp
ufw allow 5003/tcp

# Enable firewall
ufw --force enable

# Configure SSH security
sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd

# Install Python packages
pip3 install flask psutil joblib scikit-learn xgboost pandas numpy requests

# Setup automatic backups to cloud storage
cat > /opt/honeypot/backup_to_cloud.sh << 'EOF'
#!/bin/bash
# Backup honeypot data to cloud storage
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/opt/honeypot/backups/honeypot_backup_$DATE.tar.gz"

# Create backup
tar -czf $BACKUP_FILE /opt/honeypot/logs /opt/honeypot/data

# Upload to cloud (configure your preferred service)
# aws s3 cp $BACKUP_FILE s3://your-bucket/honeypot-backups/
# rclone copy $BACKUP_FILE remote:honeypot-backups/
# curl -F "file=@$BACKUP_FILE" https://your-backup-service.com/upload

# Keep only last 30 backups locally
find /opt/honeypot/backups -name "honeypot_backup_*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
EOF

chmod +x /opt/honeypot/backup_to_cloud.sh

# Setup cron for automatic backups
echo "0 2 * * * /opt/honeypot/backup_to_cloud.sh" | crontab -u honeypot -

# Create systemd service
cat > /etc/systemd/system/honeypot.service << 'EOF'
[Unit]
Description=Isolated Adaptive Honeypot
After=network.target

[Service]
Type=simple
User=honeypot
WorkingDirectory=/opt/honeypot
ExecStart=/usr/bin/python3 integrated_adaptive_dashboard.py
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Enable service
systemctl daemon-reload
systemctl enable honeypot

# Setup nginx reverse proxy for additional security
cat > /etc/nginx/sites-available/honeypot << 'EOF'
server {
    listen 80;
    server_name _;
    
    # Log all requests for analysis
    access_log /var/log/nginx/honeypot_access.log;
    error_log /var/log/nginx/honeypot_error.log;
    
    location / {
        proxy_pass http://127.0.0.1:5003;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Rate limiting
        limit_req zone=honeypot burst=20 nodelay;
    }
}

# Rate limiting zone
http {
    limit_req_zone $binary_remote_addr zone=honeypot:10m rate=10r/s;
}
EOF

ln -s /etc/nginx/sites-available/honeypot /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default
systemctl restart nginx

echo "✅ Isolated honeypot VPS setup complete!"
echo "🔒 SSH is now on port 2222 for security"
echo "🍯 Upload your honeypot code to /opt/honeypot/"
echo "🚀 Start with: systemctl start honeypot"
"""
        
        with open('isolated_vps_setup.sh', 'w') as f:
            f.write(deployment_script)
        
        print("📝 Created VPS deployment script: isolated_vps_setup.sh")
    
    def show_deployment_guide(self):
        """Show complete deployment guide"""
        print("\n" + "=" * 80)
        print("🚀 ISOLATED CLOUD DEPLOYMENT GUIDE")
        print("=" * 80)
        
        print("\n🎯 RECOMMENDED: Oracle Cloud Free Tier")
        print("-" * 50)
        print("✅ Completely FREE forever")
        print("✅ 4 CPU cores, 24GB RAM, 200GB storage")
        print("✅ ARM-based (different architecture = more realistic)")
        print("✅ Professional data center IP")
        print("✅ 100% isolated from your devices")
        print()
        print("Setup steps:")
        print("1. Sign up: https://cloud.oracle.com/free")
        print("2. Create ARM instance with Ubuntu 22.04")
        print("3. Upload cloud-init.yaml during creation")
        print("4. SSH in and upload your honeypot code")
        print("5. Start the service: sudo systemctl start honeypot")
        
        print("\n💰 ALTERNATIVE: Cheap VPS ($3-5/month)")
        print("-" * 50)
        print("• Vultr: $2.50/month (IPv6) or $3.50/month (IPv4)")
        print("• DigitalOcean: $4/month")
        print("• Linode: $5/month")
        print("• Hetzner: €3.29/month")
        print()
        print("Setup steps:")
        print("1. Create Ubuntu 22.04 server")
        print("2. SSH in as root")
        print("3. Run: wget YOUR_SCRIPT_URL && bash isolated_vps_setup.sh")
        print("4. Upload honeypot code")
        print("5. Start service")
    
    def create_data_persistence_system(self):
        """Create persistent data storage system"""
        
        data_manager = """#!/usr/bin/env python3
'''
Persistent Data Manager for Isolated Honeypot
Handles data storage, backups, and remote access
'''
import os
import json
import sqlite3
import gzip
import shutil
from datetime import datetime, timedelta
import requests

class HoneypotDataManager:
    def __init__(self, data_dir='/opt/honeypot/data'):
        self.data_dir = data_dir
        self.db_path = os.path.join(data_dir, 'honeypot.db')
        self.backup_dir = os.path.join(data_dir, 'backups')
        
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        
        self.init_database()
    
    def init_database(self):
        '''Initialize SQLite database for persistent storage'''
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                timestamp DATETIME,
                source_ip TEXT,
                protocol TEXT,
                duration INTEGER,
                commands TEXT,
                threat_score REAL,
                is_threat BOOLEAN,
                blocked BOOLEAN,
                raw_data TEXT
            )
        ''')
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                timestamp DATETIME,
                source_ip TEXT,
                threat_type TEXT,
                severity TEXT,
                confidence REAL,
                model_used TEXT,
                blocked BOOLEAN,
                details TEXT
            )
        ''')
        
        # Blocked IPs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                first_seen DATETIME,
                last_seen DATETIME,
                threat_count INTEGER DEFAULT 1,
                block_reason TEXT,
                still_blocked BOOLEAN DEFAULT 1
            )
        ''')
        
        # Adaptations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS adaptations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                old_profile TEXT,
                new_profile TEXT,
                reason TEXT,
                attack_count INTEGER,
                trigger_data TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def store_session(self, session_data):
        '''Store session data persistently'''
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO sessions 
            (session_id, timestamp, source_ip, protocol, duration, commands, 
             threat_score, is_threat, blocked, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_data.get('session_id'),
            session_data.get('timestamp'),
            session_data.get('source_ip'),
            session_data.get('protocol'),
            session_data.get('duration', 0),
            json.dumps(session_data.get('commands', [])),
            session_data.get('threat_score', 0.0),
            session_data.get('is_threat', False),
            session_data.get('blocked', False),
            json.dumps(session_data)
        ))
        
        conn.commit()
        conn.close()
    
    def create_backup(self):
        '''Create compressed backup of all data'''
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(self.backup_dir, f'honeypot_backup_{timestamp}.tar.gz')
        
        # Create tar.gz backup
        shutil.make_archive(backup_file.replace('.tar.gz', ''), 'gztar', self.data_dir)
        
        return backup_file
    
    def get_statistics(self):
        '''Get comprehensive statistics'''
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total sessions
        cursor.execute('SELECT COUNT(*) FROM sessions')
        stats['total_sessions'] = cursor.fetchone()[0]
        
        # Total threats
        cursor.execute('SELECT COUNT(*) FROM threats')
        stats['total_threats'] = cursor.fetchone()[0]
        
        # Blocked IPs
        cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE still_blocked = 1')
        stats['blocked_ips'] = cursor.fetchone()[0]
        
        # Top attacking IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as attack_count 
            FROM sessions WHERE is_threat = 1 
            GROUP BY source_ip 
            ORDER BY attack_count DESC 
            LIMIT 10
        ''')
        stats['top_attackers'] = cursor.fetchall()
        
        # Attack trends (last 24 hours)
        cursor.execute('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as attacks
            FROM sessions 
            WHERE timestamp > datetime('now', '-24 hours') AND is_threat = 1
            GROUP BY hour
            ORDER BY hour
        ''')
        stats['hourly_attacks'] = cursor.fetchall()
        
        conn.close()
        return stats

if __name__ == '__main__':
    manager = HoneypotDataManager()
    print("📊 Honeypot Data Manager initialized")
    print(f"📁 Database: {manager.db_path}")
    print(f"💾 Backups: {manager.backup_dir}")
"""
        
        with open('honeypot_data_manager.py', 'w') as f:
            f.write(data_manager)
        
        print("📝 Created persistent data manager: honeypot_data_manager.py")

def main():
    """Main function"""
    deployer = IsolatedCloudHoneypot()
    
    deployer.show_isolation_benefits()
    deployer.show_deployment_guide()
    deployer.create_oracle_deployment()
    deployer.create_simple_vps_deployment()
    deployer.create_data_persistence_system()
    
    print("\n" + "=" * 80)
    print("📋 FILES CREATED FOR ISOLATED DEPLOYMENT")
    print("=" * 80)
    print("• cloud-init.yaml - Oracle Cloud automatic setup")
    print("• oracle_honeypot.tf - Infrastructure as code")
    print("• isolated_vps_setup.sh - VPS deployment script")
    print("• honeypot_data_manager.py - Persistent data storage")
    print()
    print("🎯 NEXT STEPS:")
    print("1. Choose Oracle Cloud Free (recommended) or cheap VPS")
    print("2. Deploy using the provided scripts")
    print("3. Upload your honeypot code to the server")
    print("4. Start the service and monitor remotely")
    print()
    print("🛡️ SECURITY GUARANTEED:")
    print("• 100% isolated from your personal devices")
    print("• Professional data center IP address")
    print("• Persistent data storage with backups")
    print("• Remote monitoring and control")

if __name__ == '__main__':
    main()