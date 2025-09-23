"""
Launcher for the Complete ML-Powered Honeypot System
"""
import sys
import os

def main():
    print("🚀 Launching Complete ML-Powered Honeypot System...")
    print("=" * 60)
    
    try:
        from complete_honeypot_system import CompleteDashboard
        
        # Create and run the system
        dashboard = CompleteDashboard()
        dashboard.run(host='0.0.0.0', port=5000)
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("\n📦 Please install required packages:")
        print("   pip install flask pandas numpy scikit-learn xgboost")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n👋 System stopped by user")
        
    except Exception as e:
        print(f"\n❌ System error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()