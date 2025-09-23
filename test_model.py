"""Test script to verify the model service is working"""
import requests
import json
import numpy as np

def test_prediction():
    """Test the prediction endpoint"""
    # Sample features (5 features as expected by our dummy model)
    sample_features = [0.1, 0.2, 0.3, 0.4, 0.5]
    
    try:
        response = requests.post(
            'http://localhost:5001/predict',
            json={'features': sample_features},
            timeout=5
        )
        result = response.json()
        print("Test Prediction Result:")
        print(json.dumps(result, indent=2))
        return True
    except Exception as e:
        print(f"Error testing prediction: {e}")
        return False

def test_health():
    """Test the health check endpoint"""
    try:
        response = requests.get('http://localhost:5001/health', timeout=5)
        result = response.json()
        print("\nHealth Check:")
        print(json.dumps(result, indent=2))
        return True
    except Exception as e:
        print(f"Error testing health check: {e}")
        return False

if __name__ == '__main__':
    print("Testing ML Model Service...")
    
    # Run tests
    health_ok = test_health()
    prediction_ok = test_prediction()
    
    if health_ok and prediction_ok:
        print("\n✅ All tests passed!")
    else:
        print("\n❌ Some tests failed. Check the output above for errors.")
