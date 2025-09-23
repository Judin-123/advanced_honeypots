"""
Complete Ngrok Honeypot Setup
Easy deployment of your adaptive honeypot with ngrok
"""
import os
import json
import time
import subprocess
import threading
import requests
import webbrowser
from datetime import datetime

class NgrokHoneypotSetup:
    """Complete ngrok setup and management for honeypot"""
    
    def __init__(self):
        self.ngrok_process = None
        self.honeypot_process = None
        self.public_url = None
        self.ngrok_api_url = "http://localhost:4040/api/tunnels"
    
    def check_ngrok_installed(self):
        """Check if ngrok is installed"""
        try:
            result = subprocess.run(['ngrok', 'version'], capture_output=True, text=True)
            if result.returncode == 0:
                version = result.stdout.strip()
                print(f"✅ Ngrok found: {version}")
                return True
            else:
                print("❌ Ngrok not found")
                return False
        except FileNotFoundError:
            print("❌ Ngrok not installed")
            return False
    
    def install_ngrok_guide(self):
        """Show ngrok installation guide"""
        print("\n" + "=" * 60)
        print("📥 NGROK INSTALLATION GUIDE")
        print("=" * 60)
        print()
        print("1. Go to: https://ngrok.com/download")
        print("2. Download ngrok for Windows")
        print("3. Extract ngrok.exe to a folder (e.g., C:\\ngrok\\)")
        print("4. Add ngrok to your PATH or copy to system folder")
        print()
        print("Quick install via PowerShell (as Administrator):")
        print("   Invoke-WebRequest -Uri 'https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip' -OutFile 'ngrok.zip'")
        print("   Expand-Archive ngrok.zip")
        print("   Move-Item .\\ngrok\\ngrok.exe C:\\Windows\\System32\\")
        print()
        print("5. Sign up for free account at: https://dashboard.ngrok.com/signup")
        print("6. Get your authtoken from: https://dashboard.ngrok.com/get-started/your-authtoken")
        print("7. Run: ngrok config add-authtoken YOUR_TOKEN")
        print()
        
        # Open ngrok website
        try:
            webbrowser.open("https://ngrok.com/download")
            print("🌐 Opened ngrok download page in browser")
        except:
            pass
    
    def setup_ngrok_auth(self):
        """Help user setup ngrok authentication"""
        print("\n" + "=" * 60)
        print("🔐 NGROK AUTHENTICATION SETUP")
        print("=" * 60)
        print()
        
        # Check if already authenticated
        try:
            result = subprocess.run(['ngrok', 'config', 'check'], capture_output=True, text=True)
            if "valid" in result.stdout.lower():
                print("✅ Ngrok already authenticated!")
                return True
        except:
            pass
        
        print("1. Sign up for free ngrok account:")
        print("   https://dashboard.ngrok.com/signup")
        print()
        print("2. Get your authtoken:")
        print("   https://dashboard.ngrok.com/get-started/your-authtoken")
        print()
        print("3. Enter your authtoken when prompted")
        
        # Open auth pages
        try:
            webbrowser.open("https://dashboard.ngrok.com/get-started/your-authtoken")
            print("🌐 Opened ngrok authtoken page in browser")
        except:
            pass
        
        # Prompt for authtoken
        authtoken = input("\n🔑 Enter your ngrok authtoken: ").strip()
        
        if authtoken:
            try:
                result = subprocess.run(['ngrok', 'config', 'add-authtoken', authtoken], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print("✅ Ngrok authentication successful!")
                    return True
                else:
                    print(f"❌ Authentication failed: {result.stderr}")
                    return False
            except Exception as e:
                print(f"❌ Error setting authtoken: {e}")
                return False
        
        return False
    
    def start_honeypot(self):
        """Start the honeypot dashboard"""
        print("🍯 Starting adaptive honeypot dashboard...")
        
        try:
            # Start honeypot in background
            self.honeypot_process = subprocess.Popen(
                ['python', 'integrated_adaptive_dashboard.py'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a moment for it to start
            time.sleep(3)
            
            # Check if it's running
            if self.honeypot_process.poll() is None:
                print("✅ Honeypot dashboard started on port 5003")
                return True
            else:
                stdout, stderr = self.honeypot_process.communicate()
                print(f"❌ Honeypot failed to start: {stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Error starting honeypot: {e}")
            return False
    
    def start_ngrok_tunnel(self):
        """Start ngrok tunnel"""
        print("🌐 Creating ngrok tunnel...")
        
        try:
            # Start ngrok tunnel
            self.ngrok_process = subprocess.Popen(
                ['ngrok', 'http', '5003', '--log=stdout'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for tunnel to establish
            time.sleep(5)
            
            # Get public URL
            self.public_url = self.get_ngrok_url()
            
            if self.public_url:
                print(f"✅ Ngrok tunnel created!")
                print(f"🌍 Public URL: {self.public_url}")
                return True
            else:
                print("❌ Failed to get ngrok URL")
                return False
                
        except Exception as e:
            print(f"❌ Error starting ngrok: {e}")
            return False
    
    def get_ngrok_url(self):
        """Get the public ngrok URL"""
        try:
            # Try to get URL from ngrok API
            for attempt in range(10):  # Try for 10 seconds
                try:
                    response = requests.get(self.ngrok_api_url, timeout=2)
                    if response.status_code == 200:
                        data = response.json()
                        tunnels = data.get('tunnels', [])
                        
                        for tunnel in tunnels:
                            if tunnel.get('proto') == 'https':
                                return tunnel.get('public_url')
                        
                        # Fallback to http if https not found
                        for tunnel in tunnels:
                            if tunnel.get('proto') == 'http':
                                return tunnel.get('public_url')
                
                except requests.RequestException:
                    pass
                
                time.sleep(1)
            
            return None
            
        except Exception as e:
            print(f"Error getting ngrok URL: {e}")
            return None
    
    def show_status_dashboard(self):
        """Show real-time status"""
        print("\n" + "=" * 80)
        print("📊 HONEYPOT STATUS DASHBOARD")
        print("=" * 80)
        
        if self.public_url:
            print(f"🌍 Public URL: {self.public_url}")
            print(f"📊 Dashboard: {self.public_url}")
            print(f"🔧 Ngrok Admin: http://localhost:4040")
            print()
            
            # Try to open in browser
            try:
                webbrowser.open(self.public_url)
                print("🌐 Opened honeypot in browser")
            except:
                pass
        
        print("📈 Real-time Statistics:")
        print("-" * 40)
        
        # Monitor status
        try:
            while True:
                # Check if processes are still running
                honeypot_running = self.honeypot_process and self.honeypot_process.poll() is None
                ngrok_running = self.ngrok_process and self.ngrok_process.poll() is None
                
                # Get current time
                current_time = datetime.now().strftime("%H:%M:%S")
                
                # Show status
                honeypot_status = "🟢 RUNNING" if honeypot_running else "🔴 STOPPED"
                ngrok_status = "🟢 CONNECTED" if ngrok_running else "🔴 DISCONNECTED"
                
                print(f"\r[{current_time}] Honeypot: {honeypot_status} | Ngrok: {ngrok_status} | URL: {self.public_url or 'N/A'}", end="")
                
                # Check if both stopped
                if not honeypot_running or not ngrok_running:
                    print("\n❌ Service stopped!")
                    break
                
                time.sleep(5)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping services...")
            self.stop_services()
    
    def stop_services(self):
        """Stop honeypot and ngrok"""
        print("🛑 Stopping services...")
        
        if self.honeypot_process:
            try:
                self.honeypot_process.terminate()
                self.honeypot_process.wait(timeout=5)
                print("✅ Honeypot stopped")
            except:
                self.honeypot_process.kill()
                print("🔨 Honeypot force killed")
        
        if self.ngrok_process:
            try:
                self.ngrok_process.terminate()
                self.ngrok_process.wait(timeout=5)
                print("✅ Ngrok stopped")
            except:
                self.ngrok_process.kill()
                print("🔨 Ngrok force killed")
    
    def create_startup_scripts(self):
        """Create convenient startup scripts"""
        
        # Windows batch script
        batch_script = """@echo off
title Adaptive Honeypot with Ngrok

echo ===============================================
echo 🍯 ADAPTIVE HONEYPOT WITH NGROK
echo ===============================================
echo.

echo 🔍 Checking ngrok installation...
ngrok version >nul 2>&1
if errorlevel 1 (
    echo ❌ Ngrok not found! Please install ngrok first.
    echo 📥 Download from: https://ngrok.com/download
    pause
    exit /b 1
)

echo ✅ Ngrok found!
echo.

echo 🍯 Starting honeypot dashboard...
start /B python integrated_adaptive_dashboard.py
timeout /t 5 /nobreak >nul

echo 🌐 Creating public tunnel...
echo 📊 Ngrok dashboard will be available at: http://localhost:4040
echo.
echo ⚠️  Your honeypot will be publicly accessible!
echo 🌍 Share the ngrok URL to attract real hackers
echo.
echo 🛑 Press Ctrl+C to stop both services
echo.

ngrok http 5003

echo.
echo 👋 Services stopped
pause
"""
        
        # PowerShell script
        ps_script = """# Adaptive Honeypot with Ngrok Launcher
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "🍯 ADAPTIVE HONEYPOT WITH NGROK" -ForegroundColor Yellow
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# Check ngrok
Write-Host "🔍 Checking ngrok installation..." -ForegroundColor Blue
try {
    $ngrokVersion = & ngrok version 2>$null
    Write-Host "✅ Ngrok found: $ngrokVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Ngrok not found! Please install ngrok first." -ForegroundColor Red
    Write-Host "📥 Download from: https://ngrok.com/download" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "🍯 Starting honeypot dashboard..." -ForegroundColor Blue
$honeypotJob = Start-Job -ScriptBlock { python integrated_adaptive_dashboard.py }

Start-Sleep -Seconds 5

Write-Host "🌐 Creating public tunnel..." -ForegroundColor Blue
Write-Host "📊 Ngrok dashboard: http://localhost:4040" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  Your honeypot will be publicly accessible!" -ForegroundColor Yellow
Write-Host "🌍 Share the ngrok URL to attract real hackers" -ForegroundColor Green
Write-Host ""
Write-Host "🛑 Press Ctrl+C to stop both services" -ForegroundColor Red
Write-Host ""

try {
    & ngrok http 5003
} finally {
    Write-Host ""
    Write-Host "🛑 Stopping honeypot..." -ForegroundColor Yellow
    Stop-Job $honeypotJob -Force
    Remove-Job $honeypotJob -Force
    Write-Host "👋 Services stopped" -ForegroundColor Green
}
"""
        
        # Linux/Mac bash script
        bash_script = """#!/bin/bash

echo "==============================================="
echo "🍯 ADAPTIVE HONEYPOT WITH NGROK"
echo "==============================================="
echo

# Check ngrok
echo "🔍 Checking ngrok installation..."
if ! command -v ngrok &> /dev/null; then
    echo "❌ Ngrok not found! Please install ngrok first."
    echo "📥 Download from: https://ngrok.com/download"
    exit 1
fi

echo "✅ Ngrok found: $(ngrok version)"
echo

# Start honeypot
echo "🍯 Starting honeypot dashboard..."
python3 integrated_adaptive_dashboard.py &
HONEYPOT_PID=$!

sleep 5

# Start ngrok
echo "🌐 Creating public tunnel..."
echo "📊 Ngrok dashboard: http://localhost:4040"
echo
echo "⚠️  Your honeypot will be publicly accessible!"
echo "🌍 Share the ngrok URL to attract real hackers"
echo
echo "🛑 Press Ctrl+C to stop both services"
echo

# Trap Ctrl+C
trap "echo; echo '🛑 Stopping services...'; kill $HONEYPOT_PID 2>/dev/null; echo '👋 Services stopped'; exit" INT

ngrok http 5003

# Cleanup
kill $HONEYPOT_PID 2>/dev/null
echo "👋 Services stopped"
"""
        
        # Write scripts
        with open('start_honeypot.bat', 'w') as f:
            f.write(batch_script)
        
        with open('start_honeypot.ps1', 'w') as f:
            f.write(ps_script)
        
        with open('start_honeypot.sh', 'w') as f:
            f.write(bash_script)
        
        # Make bash script executable
        try:
            os.chmod('start_honeypot.sh', 0o755)
        except:
            pass
        
        print("📝 Created startup scripts:")
        print("   • start_honeypot.bat (Windows Command Prompt)")
        print("   • start_honeypot.ps1 (Windows PowerShell)")
        print("   • start_honeypot.sh (Linux/Mac)")
    
    def run_complete_setup(self):
        """Run the complete ngrok honeypot setup"""
        print("=" * 80)
        print("🚀 NGROK HONEYPOT COMPLETE SETUP")
        print("=" * 80)
        print()
        
        # Step 1: Check ngrok
        if not self.check_ngrok_installed():
            self.install_ngrok_guide()
            input("\nPress Enter after installing ngrok...")
            
            if not self.check_ngrok_installed():
                print("❌ Please install ngrok first and try again")
                return False
        
        # Step 2: Setup authentication
        if not self.setup_ngrok_auth():
            print("❌ Ngrok authentication required")
            return False
        
        # Step 3: Create scripts
        self.create_startup_scripts()
        
        # Step 4: Start services
        print("\n🚀 Starting honeypot services...")
        
        if not self.start_honeypot():
            return False
        
        if not self.start_ngrok_tunnel():
            self.stop_services()
            return False
        
        # Step 5: Show dashboard
        self.show_status_dashboard()
        
        return True

def main():
    """Main setup function"""
    setup = NgrokHoneypotSetup()
    
    print("🍯 Welcome to Ngrok Honeypot Setup!")
    print()
    print("This will:")
    print("1. Check/install ngrok")
    print("2. Setup authentication")
    print("3. Start your adaptive honeypot")
    print("4. Create public tunnel")
    print("5. Give you a public URL to share")
    print()
    
    choice = input("Ready to start? (y/n): ").lower().strip()
    
    if choice == 'y':
        setup.run_complete_setup()
    else:
        print("👋 Setup cancelled")
        
        # Still create scripts for later use
        setup.create_startup_scripts()
        print("\n📝 Startup scripts created for when you're ready!")

if __name__ == '__main__':
    main()