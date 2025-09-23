@echo off
echo ===============================================
echo 🚀 UPLOADING HONEYPOT TO ORACLE CLOUD
echo ===============================================
echo.

set SERVER_IP=129.154.41.111
set KEY_PATH=path\to\your\private\key.pem

echo 📤 Uploading honeypot files to %SERVER_IP%...
echo.

echo Uploading main dashboard...
scp -i %KEY_PATH% integrated_adaptive_dashboard.py ubuntu@%SERVER_IP%:/opt/honeypot/

echo Uploading adaptive system...
scp -i %KEY_PATH% adaptive_honeypot_system.py ubuntu@%SERVER_IP%:/opt/honeypot/

echo Uploading ML models...
scp -i %KEY_PATH% -r trained_models ubuntu@%SERVER_IP%:/opt/honeypot/

echo Uploading logs...
scp -i %KEY_PATH% -r logs ubuntu@%SERVER_IP%:/opt/honeypot/

echo.
echo ✅ Upload complete!
echo.
echo 🔧 Now SSH into server and start honeypot:
echo ssh -i %KEY_PATH% ubuntu@%SERVER_IP%
echo sudo systemctl start honeypot
echo.
echo 🌐 Dashboard will be available at:
echo http://%SERVER_IP%:5003
echo.
pause