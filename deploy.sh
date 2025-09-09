#!/bin/bash

# ML-Powered Honeypot Deployment Script
# This script automates the deployment process

set -e  # Exit on any error

echo "🕷️  ML-Powered Honeypot Deployment"
echo "=================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root (use sudo)"
    exit 1
fi

# Update system
echo "📦 Updating system packages..."
apt update

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
pip3 install -r requirements.txt

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs models data templates

# Set up Cowrie (if not already installed)
if [ ! -d "/opt/cowrie" ]; then
    echo "🔧 Setting up Cowrie honeypot..."
    python3 scripts/setup_cowrie.py
else
    echo "✅ Cowrie already installed"
fi

# Start Elasticsearch
echo "🔍 Starting Elasticsearch..."
systemctl start elasticsearch
systemctl enable elasticsearch

# Wait for Elasticsearch to be ready
echo "⏳ Waiting for Elasticsearch to start..."
sleep 10

# Test Elasticsearch connection
if curl -s http://localhost:9200 > /dev/null; then
    echo "✅ Elasticsearch is running"
else
    echo "⚠️  Elasticsearch may not be ready yet"
fi

# Start Cowrie
echo "🚀 Starting Cowrie honeypot..."
systemctl start cowrie
systemctl enable cowrie

# Wait for Cowrie to start
sleep 5

# Test system
echo "🧪 Running system tests..."
python3 scripts/test_system.py

echo ""
echo "🎉 Deployment completed!"
echo ""
echo "Next steps:"
echo "1. Start the ML honeypot: python3 main.py"
echo "2. Access dashboard: http://localhost:5000"
echo "3. Test SSH connection: ssh -p 2222 admin@localhost"
echo ""
echo "Logs:"
echo "- Application: tail -f logs/honeypot.log"
echo "- Cowrie: tail -f /var/log/cowrie/cowrie.json"
echo "- System: journalctl -u cowrie -f"
