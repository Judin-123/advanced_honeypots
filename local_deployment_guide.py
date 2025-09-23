"""
Local Deployment Guide - Deploy honeypot without cloud servers
Multiple options for exposing your honeypot to the internet
"""
import os
import json
import subprocess
import platform
import socket

class LocalDeploymentGuide:
    """Guide for deploying honeypot locally with internet exposure"""
    
    def __init__(self):
        self.system = platform.system()
        self.local_ip = self.get_local_ip()
        
    def get_local_ip(self):
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def show_deployment_options(self):
        """Show all deployment options"""
        print("=" * 80)
        print("🌐 HONEYPOT DEPLOYMENT OPTIONS (No Cloud Server Needed)")
        print("=" * 80)
        print()
        
        print("🏠 OPTION 1: Home Network Deployment")
        print("   • Use your home internet connection")
        print("   • Port forward through your router")
        print("   • Free but uses your home IP")
        print()
        
        print("🔗 OPTION 2: Ngrok Tunneling (Recommended)")
        print("   • Instant public URL")
        print("   • No router configuration needed")
        print("   • Free tier available")
        print()
        
        print("📱 OPTION 3: Cloudflare Tunnel")
        print("   • Free secure tunneling")
        print("   • DDoS protection included")
        print("   • Custom domain support")
        print()
        
        print("🖥️ OPTION 4: VPS (Cheap Options)")
        print("   • $3-5/month VPS providers")
        print("   • Full control and dedicated IP")
        print("   • Professional deployment")
        print()
        
        print("🏢 OPTION 5: Oracle Cloud Free Tier")
        print("   • Completely free forever")
        print("   • ARM-based instances")
        print("   • 24GB RAM, 4 CPUs available")
        print()
        
        self.show_detailed_guides()
    
    def show_detailed_guides(self):
        """Show detailed setup guides for each option"""
        
        print("\n" + "=" * 60)
        print("📋 DETAILED SETUP GUIDES")
        print("=" * 60)
        
        self.guide_ngrok()
        self.guide_cloudflare_tunnel()
        self.guide_port_forwarding()
        self.guide_oracle_free()
        self.guide_cheap_vps()
    
    def guide_ngrok(self):
        """Ngrok setup guide"""
        print("\n🔗 NGROK SETUP (Easiest Option)")
        print("-" * 40)
        print("1. Download ngrok: https://ngrok.com/download")
        print("2. Sign up for free account")
        print("3. Install and authenticate:")
        print("   ngrok config add-authtoken YOUR_TOKEN")
        print("4. Run your honeypot dashboard:")
        print("   python real_dashboard.py")
        print("5. In another terminal, expose it:")
        print("   ngrok http 5002")
        print("6. Ngrok will give you a public URL like:")
        print("   https://abc123.ngrok.io")
        print()
        print("✅ Pros: Instant, no configuration, HTTPS included")
        print("❌ Cons: Random URLs, limited free hours")
        
        # Create ngrok startup script
        self.create_ngrok_script()
    
    def guide_cloudflare_tunnel(self):
        """Cloudflare Tunnel setup guide"""
        print("\n☁️ CLOUDFLARE TUNNEL SETUP (Free & Secure)")
        print("-" * 40)
        print("1. Sign up at cloudflare.com (free)")
        print("2. Download cloudflared:")
        print("   Windows: https://github.com/cloudflare/cloudflared/releases")
        print("3. Login to Cloudflare:")
        print("   cloudflared tunnel login")
        print("4. Create a tunnel:")
        print("   cloudflared tunnel create honeypot")
        print("5. Configure tunnel (creates config file)")
        print("6. Run tunnel:")
        print("   cloudflared tunnel run honeypot")
        print()
        print("✅ Pros: Free, secure, DDoS protection, custom domains")
        print("❌ Cons: Requires domain (can use free .tk/.ml)")
        
        # Create cloudflare config
        self.create_cloudflare_config()
    
    def guide_port_forwarding(self):
        """Port forwarding setup guide"""
        print("\n🏠 HOME ROUTER PORT FORWARDING")
        print("-" * 40)
        print(f"Your local IP: {self.local_ip}")
        print("1. Access your router admin panel (usually 192.168.1.1)")
        print("2. Find 'Port Forwarding' or 'Virtual Servers'")
        print("3. Add new rule:")
        print("   - External Port: 80 (or 8080)")
        print("   - Internal Port: 5002")
        print(f"   - Internal IP: {self.local_ip}")
        print("   - Protocol: TCP")
        print("4. Find your public IP: whatismyipaddress.com")
        print("5. Access via: http://YOUR_PUBLIC_IP:80")
        print()
        print("✅ Pros: Free, full control")
        print("❌ Cons: Exposes home IP, router config needed")
        
        # Show router access helper
        self.show_router_access_helper()
    
    def guide_oracle_free(self):
        """Oracle Cloud Free Tier guide"""
        print("\n🆓 ORACLE CLOUD FREE TIER (Best Free Option)")
        print("-" * 40)
        print("1. Sign up: https://cloud.oracle.com/free")
        print("2. Create VM instance:")
        print("   - Shape: VM.Standard.A1.Flex (ARM)")
        print("   - CPUs: 4 (free)")
        print("   - RAM: 24GB (free)")
        print("   - Storage: 200GB (free)")
        print("3. Configure security rules (open ports)")
        print("4. Upload your honeypot code")
        print("5. Install Python and dependencies")
        print("6. Run honeypot on public IP")
        print()
        print("✅ Pros: Completely free forever, powerful specs")
        print("❌ Cons: ARM architecture, setup complexity")
        
        # Create Oracle deployment script
        self.create_oracle_deployment_script()
    
    def guide_cheap_vps(self):
        """Cheap VPS options"""
        print("\n💰 CHEAP VPS OPTIONS ($3-5/month)")
        print("-" * 40)
        print("Recommended providers:")
        print("• Vultr: $2.50/month (IPv6 only), $3.50/month (IPv4)")
        print("• DigitalOcean: $4/month droplets")
        print("• Linode: $5/month nanode")
        print("• Hetzner: €3.29/month CX11")
        print("• Contabo: €3.99/month VPS S")
        print()
        print("Setup steps:")
        print("1. Choose provider and create account")
        print("2. Deploy Ubuntu 22.04 server")
        print("3. SSH into server")
        print("4. Upload honeypot code")
        print("5. Install dependencies and run")
        print()
        print("✅ Pros: Dedicated IP, full control, professional")
        print("❌ Cons: Small monthly cost")
    
    def create_ngrok_script(self):
        """Create ngrok startup script"""
        script_content = """#!/bin/bash
# Ngrok Honeypot Deployment Script

echo "🔗 Starting Honeypot with Ngrok..."

# Start honeypot in background
python real_dashboard.py &
HONEYPOT_PID=$!

# Wait for honeypot to start
sleep 5

# Start ngrok tunnel
echo "🌐 Creating public tunnel..."
ngrok http 5002 --log=stdout &
NGROK_PID=$!

echo "✅ Honeypot running with public access!"
echo "📊 Check ngrok dashboard: http://localhost:4040"
echo "🛑 Press Ctrl+C to stop both services"

# Wait for interrupt
trap "kill $HONEYPOT_PID $NGROK_PID; exit" INT
wait
"""
        
        with open('start_ngrok_honeypot.sh', 'w') as f:
            f.write(script_content)
        
        # Windows batch version
        batch_content = """@echo off
echo 🔗 Starting Honeypot with Ngrok...

REM Start honeypot in background
start /B python real_dashboard.py

REM Wait for honeypot to start
timeout /t 5 /nobreak

REM Start ngrok tunnel
echo 🌐 Creating public tunnel...
ngrok http 5002

echo ✅ Honeypot running with public access!
pause
"""
        
        with open('start_ngrok_honeypot.bat', 'w') as f:
            f.write(batch_content)
        
        print("📝 Created startup scripts:")
        print("   • start_ngrok_honeypot.sh (Linux/Mac)")
        print("   • start_ngrok_honeypot.bat (Windows)")
    
    def create_cloudflare_config(self):
        """Create Cloudflare tunnel configuration"""
        config = {
            "tunnel": "YOUR_TUNNEL_ID",
            "credentials-file": "/path/to/credentials.json",
            "ingress": [
                {
                    "hostname": "honeypot.yourdomain.com",
                    "service": "http://localhost:5002"
                },
                {
                    "service": "http_status:404"
                }
            ]
        }
        
        with open('cloudflare_tunnel_config.yml', 'w') as f:
            import yaml
            try:
                yaml.dump(config, f, default_flow_style=False)
            except:
                # Fallback if yaml not available
                f.write(str(config))
        
        print("📝 Created cloudflare_tunnel_config.yml")
    
    def show_router_access_helper(self):
        """Help user access their router"""
        print("\n🔧 Router Access Helper:")
        
        # Try to detect router IP
        if self.system == "Windows":
            try:
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'Default Gateway' in line:
                        gateway = line.split(':')[-1].strip()
                        if gateway:
                            print(f"   Detected router IP: {gateway}")
                            print(f"   Try accessing: http://{gateway}")
                            break
            except:
                pass
        
        print("   Common router IPs:")
        print("   • http://192.168.1.1")
        print("   • http://192.168.0.1") 
        print("   • http://10.0.0.1")
        print("   • http://192.168.1.254")
    
    def create_oracle_deployment_script(self):
        """Create Oracle Cloud deployment script"""
        script = """#!/bin/bash
# Oracle Cloud Honeypot Deployment Script

echo "🏛️ Setting up honeypot on Oracle Cloud..."

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install -y python3 python3-pip git

# Install required Python packages
pip3 install flask psutil joblib scikit-learn xgboost

# Clone or upload your honeypot code
# git clone YOUR_HONEYPOT_REPO

# Configure firewall (Oracle Cloud uses iptables)
sudo iptables -I INPUT -p tcp --dport 5002 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 22 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT

# Save iptables rules
sudo iptables-save > /etc/iptables/rules.v4

# Create systemd service for honeypot
sudo tee /etc/systemd/system/honeypot.service > /dev/null <<EOF
[Unit]
Description=Adaptive Honeypot System
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/ml-honeypot
ExecStart=/usr/bin/python3 real_dashboard.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable honeypot
sudo systemctl start honeypot

echo "✅ Honeypot deployed on Oracle Cloud!"
echo "🌐 Access via your instance's public IP on port 5002"
"""
        
        with open('oracle_deploy.sh', 'w') as f:
            f.write(script)
        
        print("📝 Created oracle_deploy.sh deployment script")
    
    def create_docker_deployment(self):
        """Create Docker deployment files"""
        dockerfile = """FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 5002

# Run the application
CMD ["python", "real_dashboard.py"]
"""
        
        docker_compose = """version: '3.8'

services:
  honeypot:
    build: .
    ports:
      - "5002:5002"
    volumes:
      - ./logs:/app/logs
      - ./trained_models:/app/trained_models
    restart: unless-stopped
    environment:
      - PYTHONUNBUFFERED=1
    
  # Optional: Add nginx reverse proxy
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - honeypot
    restart: unless-stopped
"""
        
        nginx_conf = """events {
    worker_connections 1024;
}

http {
    upstream honeypot {
        server honeypot:5002;
    }
    
    server {
        listen 80;
        server_name _;
        
        location / {
            proxy_pass http://honeypot;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
}
"""
        
        with open('Dockerfile', 'w') as f:
            f.write(dockerfile)
        
        with open('docker-compose.yml', 'w') as f:
            f.write(docker_compose)
        
        with open('nginx.conf', 'w') as f:
            f.write(nginx_conf)
        
        print("📝 Created Docker deployment files:")
        print("   • Dockerfile")
        print("   • docker-compose.yml") 
        print("   • nginx.conf")
    
    def show_security_recommendations(self):
        """Show security recommendations for deployment"""
        print("\n" + "=" * 60)
        print("🔒 SECURITY RECOMMENDATIONS")
        print("=" * 60)
        
        print("\n🛡️ Network Security:")
        print("• Use a separate network/VLAN for honeypot")
        print("• Monitor all traffic to/from honeypot")
        print("• Set up proper logging and alerting")
        print("• Use fail2ban for additional protection")
        
        print("\n🔐 System Security:")
        print("• Keep system updated")
        print("• Use strong SSH keys (disable password auth)")
        print("• Configure proper firewall rules")
        print("• Regular security audits")
        
        print("\n📊 Monitoring:")
        print("• Set up log aggregation (ELK stack)")
        print("• Monitor system resources")
        print("• Alert on suspicious activity")
        print("• Regular backup of logs and data")
        
        print("\n⚖️ Legal Considerations:")
        print("• Check local laws about honeypots")
        print("• Consider liability issues")
        print("• Document everything for evidence")
        print("• Consider coordinated disclosure")

def main():
    """Main deployment guide"""
    guide = LocalDeploymentGuide()
    
    guide.show_deployment_options()
    guide.create_docker_deployment()
    guide.show_security_recommendations()
    
    print("\n" + "=" * 80)
    print("🚀 QUICK START RECOMMENDATIONS")
    print("=" * 80)
    print()
    print("For beginners: Start with Ngrok")
    print("1. Download ngrok and sign up")
    print("2. Run: python real_dashboard.py")
    print("3. Run: ngrok http 5002")
    print("4. Share the ngrok URL to attract attackers")
    print()
    print("For production: Use Oracle Cloud Free Tier")
    print("1. Sign up for Oracle Cloud")
    print("2. Create ARM instance (free)")
    print("3. Upload code and run oracle_deploy.sh")
    print("4. Configure security groups")
    print()
    print("📁 Files created:")
    print("• start_ngrok_honeypot.sh/bat - Ngrok startup")
    print("• oracle_deploy.sh - Oracle Cloud deployment")
    print("• docker-compose.yml - Docker deployment")
    print("• cloudflare_tunnel_config.yml - Cloudflare setup")

if __name__ == '__main__':
    main()