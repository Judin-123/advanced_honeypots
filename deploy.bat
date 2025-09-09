@echo off
REM ML-Powered Honeypot Deployment Script for Windows
REM This script automates the deployment process

echo 🕷️  ML-Powered Honeypot Deployment
echo ==================================

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ❌ This script must be run as administrator
    pause
    exit /b 1
)

REM Install Python dependencies
echo 🐍 Installing Python dependencies...
pip install -r requirements.txt

REM Create necessary directories
echo 📁 Creating directories...
if not exist logs mkdir logs
if not exist models mkdir models
if not exist data mkdir data
if not exist templates mkdir templates

REM Note: Cowrie and Elasticsearch setup requires Linux
echo ⚠️  Note: Full deployment requires Linux environment
echo    For Windows development, you can:
echo    1. Use WSL2 with Ubuntu
echo    2. Use Docker containers
echo    3. Run on a Linux VM

echo.
echo 🧪 Running system tests...
python scripts/test_system.py

echo.
echo 🎉 Setup completed!
echo.
echo Next steps:
echo 1. For full deployment, use Linux or WSL2
echo 2. Run: python main.py
echo 3. Access dashboard: http://localhost:5000
echo.
pause
