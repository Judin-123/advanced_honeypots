""
Local Development Launcher for ML Honeypot
This script provides a simple way to run the honeypot locally without Docker.
"""
import os
import sys
import subprocess
from pathlib import Path
import webbrowser
import time

def check_python_version():
    """Ensure we're using Python 3.7 or higher"""
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required")
        sys.exit(1)

def install_requirements():
    """Install required Python packages"""
    print("Installing required packages...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

def setup_environment():
    """Set up the local environment"""
    # Create necessary directories
    Path("data").mkdir(exist_ok=True)
    Path("models").mkdir(exist_ok=True)
    Path("logs").mkdir(exist_ok=True)

def start_services():
    """Start the required services"""
    print("\nStarting services...")
    
    # Start the ML model service
    print("Starting ML Model Service...")
    ml_process = subprocess.Popen(
        [sys.executable, "src/ml/model_service.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Start the web interface
    print("Starting Web Interface...")
    web_process = subprocess.Popen(
        [sys.executable, "app.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Open the browser
    time.sleep(2)  # Give the server a moment to start
    webbrowser.open("http://localhost:5000")
    
    return ml_process, web_process

def main():
    """Main function"""
    print("=" * 50)
    print("ML-Powered Honeypot - Local Development")
    print("=" * 50)
    
    try:
        check_python_version()
        install_requirements()
        setup_environment()
        
        print("\nEnvironment setup complete!")
        print("Starting services...")
        
        ml_proc, web_proc = start_services()
        
        print("\nHoneypot is running!")
        print("Press Ctrl+C to stop")
        
        # Keep the script running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            ml_proc.terminate()
            web_proc.terminate()
            print("Done!")
            
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
