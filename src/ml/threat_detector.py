"""
Threat Detection Module
Uses the trained XGBoost model to detect threats in real-time.
"""

import os
import json
import logging
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatDetector:
    """
    Threat detector that uses a trained XGBoost model to classify network traffic.
    """
    
    def __init__(self, model_path: str = None, config_path: str = None):
        """
        Initialize the threat detector.
        
        Args:
            model_path: Path to the trained XGBoost model file
            config_path: Path to the configuration file
        """
        self.model = None
        self.scaler = None
        self.label_mapping = None
        self.feature_columns = None
        
        # Default paths
        self.base_dir = Path(__file__).parent.parent.parent
        self.default_model_path = self.base_dir / "models/xgb_cic_ids2017.model"
        self.default_scaler_path = self.base_dir / "models/scaler.pkl"
        self.default_mapping_path = self.base_dir / "models/label_mapping.json"
        
        # Load model and resources
        self._load_model(model_path or str(self.default_model_path))
        self._load_scaler()
        self._load_label_mapping()
    
    def _load_model(self, model_path: str) -> None:
        """Load the XGBoost model from file."""
        try:
            self.model = xgb.Booster()
            self.model.load_model(model_path)
            logger.info(f"Loaded model from {model_path}")
        except Exception as e:
            logger.error(f"Error loading model from {model_path}: {e}")
            raise
    
    def _load_scaler(self) -> None:
        """Load the feature scaler."""
        try:
            if self.default_scaler_path.exists():
                self.scaler = joblib.load(self.default_scaler_path)
                logger.info(f"Loaded feature scaler from {self.default_scaler_path}")
            else:
                logger.warning(f"Scaler file not found at {self.default_scaler_path}")
        except Exception as e:
            logger.error(f"Error loading scaler: {e}")
            self.scaler = None
    
    def _load_label_mapping(self) -> None:
        """Load the label mapping for attack types."""
        try:
            if self.default_mapping_path.exists():
                with open(self.default_mapping_path, 'r') as f:
                    self.label_mapping = json.load(f)
                logger.info(f"Loaded label mapping from {self.default_mapping_path}")
            else:
                logger.warning(f"Label mapping file not found at {self.default_mapping_path}")
                self.label_mapping = {}
        except Exception as e:
            logger.error(f"Error loading label mapping: {e}")
            self.label_mapping = {}
    
    def preprocess_features(self, features: Dict[str, Any]) -> np.ndarray:
        """
        Preprocess input features for the model.
        
        Args:
            features: Dictionary of feature names and values
            
        Returns:
            Numpy array of preprocessed features
        """
        try:
            # Convert to DataFrame for easier manipulation
            df = pd.DataFrame([features])
            
            # Ensure all required columns are present
            if hasattr(self, 'feature_columns'):
                for col in self.feature_columns:
                    if col not in df.columns:
                        df[col] = 0  # Fill missing columns with 0
            
            # Convert all columns to numeric, coercing errors to NaN
            for col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce')
            
            # Fill NaN values with 0
            df = df.fillna(0)
            
            # Scale features if scaler is available
            if self.scaler is not None:
                df_scaled = self.scaler.transform(df)
                return df_scaled
                
            return df.values
            
        except Exception as e:
            logger.error(f"Error preprocessing features: {e}")
            raise
    
    def detect_threat(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect if the input features represent a threat.
        
        Args:
            features: Dictionary of feature names and values
            
        Returns:
            Dictionary containing:
            - is_threat: bool indicating if a threat was detected
            - confidence: float confidence score (0-1)
            - threat_type: str name of the threat type if applicable
            - details: dict with additional detection details
        """
        try:
            # Preprocess features
            processed_features = self.preprocess_features(features)
            
            # Make prediction
            dmatrix = xgb.DMatrix(processed_features)
            prediction = self.model.predict(dmatrix)[0]
            
            # Convert to threat score (0-1)
            threat_score = float(prediction)
            is_threat = threat_score >= 0.5
            
            # Get threat type if label mapping is available
            threat_type = "Unknown"
            if self.label_mapping:
                # For binary classification, we just have Normal/Attack
                threat_type = "Attack" if is_threat else "Normal"
            
            return {
                'is_threat': bool(is_threat),
                'confidence': float(threat_score if is_threat else 1 - threat_score),
                'threat_type': threat_type,
                'details': {
                    'raw_prediction': float(prediction),
                    'features_used': list(features.keys())
                }
            }
            
        except Exception as e:
            logger.error(f"Error in threat detection: {e}")
            return {
                'is_threat': False,
                'confidence': 0.0,
                'threat_type': 'Error',
                'details': {
                    'error': str(e)
                }
            }
    
    def batch_detect(self, features_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect threats in a batch of feature sets.
        
        Args:
            features_list: List of feature dictionaries
            
        Returns:
            List of detection results
        """
        return [self.detect_threat(features) for features in features_list]

# Example usage
if __name__ == "__main__":
    # Initialize detector
    detector = ThreatDetector()
    
    # Example feature set (should match the training data features)
    example_features = {
        'Flow Duration': 1000,
        'Total Fwd Packets': 10,
        'Total Backward Packets': 5,
        'Total Length of Fwd Packets': 500,
        'Total Length of Bwd Packets': 250,
        'Fwd Packet Length Max': 100,
        'Fwd Packet Length Min': 40,
        'Fwd Packet Length Mean': 50,
        'Fwd Packet Length Std': 20,
        'Bwd Packet Length Max': 60,
        'Bwd Packet Length Min': 30,
        'Bwd Packet Length Mean': 45,
        'Bwd Packet Length Std': 15,
        'Flow Bytes/s': 1000,
        'Flow Packets/s': 10,
        'Flow IAT Mean': 100,
        'Flow IAT Std': 20,
        'Flow IAT Max': 200,
        'Flow IAT Min': 50,
        'Fwd IAT Total': 500,
        'Fwd IAT Mean': 100,
        'Fwd IAT Std': 20,
        'Fwd IAT Max': 200,
        'Fwd IAT Min': 50,
        'Bwd IAT Total': 300,
        'Bwd IAT Mean': 60,
        'Bwd IAT Std': 15,
        'Bwd IAT Max': 100,
        'Bwd IAT Min': 30,
        'Fwd PSH Flags': 0,
        'Bwd PSH Flags': 0,
        'Fwd URG Flags': 0,
        'Bwd URG Flags': 0,
        'Fwd Header Length': 100,
        'Bwd Header Length': 50,
        'Fwd Packets/s': 10,
        'Bwd Packets/s': 5,
        'Min Packet Length': 30,
        'Max Packet Length': 100,
        'Packet Length Mean': 50,
        'Packet Length Std': 20,
        'Packet Length Variance': 400,
        'FIN Flag Count': 0,
        'SYN Flag Count': 1,
        'RST Flag Count': 0,
        'PSH Flag Count': 0,
        'ACK Flag Count': 1,
        'URG Flag Count': 0,
        'CWE Flag Count': 0,
        'ECE Flag Count': 0,
        'Down/Up Ratio': 0.5,
        'Average Packet Size': 50,
        'Avg Fwd Segment Size': 50,
        'Avg Bwd Segment Size': 45,
        'Fwd Header Length.1': 100,
        'Fwd Avg Bytes/Bulk': 0,
        'Fwd Avg Packets/Bulk': 0,
        'Fwd Avg Bulk Rate': 0,
        'Bwd Avg Bytes/Bulk': 0,
        'Bwd Avg Packets/Bulk': 0,
        'Bwd Avg Bulk Rate': 0,
        'Subflow Fwd Packets': 10,
        'Subflow Fwd Bytes': 500,
        'Subflow Bwd Packets': 5,
        'Subflow Bwd Bytes': 250,
        'Init_Win_bytes_forward': 8192,
        'Init_Win_bytes_backward': 8192,
        'act_data_pkt_fwd': 0,
        'min_seg_size_forward': 20
    }
    
    # Detect threat
    result = detector.detect_threat(example_features)
    print("\nThreat Detection Result:")
    print(f"Is Threat: {result['is_threat']}")
    print(f"Confidence: {result['confidence']:.4f}")
    print(f"Threat Type: {result['threat_type']}")
