"""
Simple ML Model Service
Handles loading the model and making predictions
"""
import os
import json
import joblib
import numpy as np
from flask import Flask, request, jsonify

app = Flask(__name__)

class ModelService:
    def __init__(self, model_path=None):
        self.model = None
        self.scaler = None
        self.load_model(model_path)
    
    def load_model(self, model_path):
        """Load the trained model and scaler"""
        try:
            if model_path and os.path.exists(model_path):
                self.model = joblib.load(model_path)
            # If no model exists, we'll use a dummy model for demo
            elif not hasattr(self, 'model') or self.model is None:
                from sklearn.ensemble import RandomForestClassifier
                print("No model found. Using a dummy model for demo purposes.")
                self.model = RandomForestClassifier()
                # Train on dummy data
                X = np.random.rand(100, 5)
                y = np.random.randint(0, 2, 100)
                self.model.fit(X, y)
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def predict(self, data):
        """Make a prediction"""
        try:
            # Convert input to numpy array if it's not already
            if not isinstance(data, np.ndarray):
                data = np.array(data).reshape(1, -1)
            
            # Make prediction
            prediction = self.model.predict_proba(data)[0]
            
            return {
                'is_threat': bool(prediction[1] > 0.5),
                'confidence': float(prediction[1]),
                'threat_score': float(prediction[1])
            }
        except Exception as e:
            print(f"Prediction error: {e}")
            return {
                'error': str(e),
                'is_threat': False,
                'confidence': 0.0
            }

# Initialize the model service
model_service = ModelService("models/xgb_cic_ids2017.model" if os.path.exists("models/xgb_cic_ids2017.model") else None)

@app.route('/predict', methods=['POST'])
def predict():
    """Prediction endpoint"""
    try:
        data = request.get_json()
        if not data or 'features' not in data:
            return jsonify({'error': 'No features provided'}), 400
        
        result = model_service.predict(data['features'])
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'model_loaded': model_service.model is not None})

def run_server(host='0.0.0.0', port=5001):
    """Run the Flask server"""
    print(f"Starting ML Model Service on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)

if __name__ == '__main__':
    run_server()
