@echo off
echo ===============================================
echo 🚀 UPLOADING HONEYPOT TO ORACLE CLOUD
echo ===============================================
echo.

set SERVER_IP=129.154.41.111
set KEY_FILE=oracle-key.pem

echo 📤 Uploading honeypot files to %SERVER_IP%...
echo.

echo [1/4] Uploading main dashboard...
scp -i %KEY_FILE% integrated_adaptive_dashboard.py ubuntu@%SERVER_IP%:/opt/honeypot/

echo [2/4] Uploading adaptive system...
scp -i %KEY_FILE% adaptive_honeypot_system.py ubuntu@%SERVER_IP%:/opt/honeypot/

echo [3/4] Uploading ML models...
scp -i %KEY_FILE% -r trained_models ubuntu@%SERVER_IP%:/opt/honeypot/

echo [4/4] Uploading sample logs...
scp -i %KEY_FILE% -r logs ubuntu@%SERVER_IP%:/opt/honeypot/

echo.
echo ✅ Upload complete!
echo.
echo 🔧 Next steps:
echo 1. SSH into server: ssh -i %KEY_FILE% ubuntu@%SERVER_IP%
echo 2. Start honeypot: sudo systemctl start honeypot
echo 3. Check status: sudo systemctl status honeypot
echo 4. View dashboard: http://%SERVER_IP%:5003
echo.
pause