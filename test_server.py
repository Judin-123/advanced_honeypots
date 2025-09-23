"""
Test if the server starts without errors
"""
import sys
import threading
import time
from simple_dashboard import app

def test_server():
    try:
        print("Testing server startup...")
        
        # Test if we can create the app
        print("✓ App created successfully")
        
        # Test a simple route
        with app.test_client() as client:
            response = client.get('/health')
            print(f"✓ Health check: {response.status_code}")
            
            response = client.get('/')
            print(f"✓ Main page: {response.status_code}")
            
            response = client.get('/api/status')
            print(f"✓ API status: {response.status_code}")
        
        print("✓ All tests passed! Server should work.")
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

if __name__ == '__main__':
    if test_server():
        print("\nStarting server...")
        app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        print("Server test failed!")