#!/bin/bash

echo "ISOLATED HONEYPOT VPS SETUP"
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

echo "Isolated honeypot VPS setup complete!"
echo "SSH is now on port 2222 for security"
echo "Upload your honeypot code to /opt/honeypot/"
echo "Start with: systemctl start honeypot"