"""
Threat Classifier for ML-Powered Honeypot
Uses XGBoost to classify attackers into threat levels: scanner, amateur, advanced
"""

import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any
import logging
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

logger = logging.getLogger(__name__)

class ThreatClassifier:
    """XGBoost-based threat classifier for honeypot attackers"""
    
    def __init__(self, model_path: str = "models/threat_classifier.pkl"):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = None
        self.class_labels = ['scanner', 'amateur', 'advanced']
        self.is_trained = False
        
        # Load existing model if available
        self.load_model()
    
    def train(self, features_df: pd.DataFrame, labels: List[str] = None) -> Dict[str, Any]:
        """
        Train the XGBoost classifier
        
        Args:
            features_df: DataFrame with extracted features
            labels: Optional ground truth labels (for supervised learning)
            
        Returns:
            Training metrics and model performance
        """
        if features_df.empty:
            logger.error("No features provided for training")
            return {"error": "No features provided"}
        
        # Prepare features
        feature_cols = self._get_feature_columns(features_df)
        X = features_df[feature_cols].fillna(0)
        
        # Generate synthetic labels if not provided (for initial training)
        if labels is None:
            labels = self._generate_synthetic_labels(features_df)
        
        # Encode labels
        y = self._encode_labels(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train XGBoost model
        self.model = xgb.XGBClassifier(
            n_estimators=100,
            max_depth=6,
            learning_rate=0.1,
            random_state=42,
            eval_metric='mlogloss',
            objective='multi:softprob',
            num_class=len(self.class_labels)
        )
        
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate model
        y_pred = self.model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        # Generate classification report
        class_report = classification_report(
            y_test, y_pred, 
            target_names=self.class_labels,
            output_dict=True
        )
        
        # Store feature columns for later use
        self.feature_columns = feature_cols
        self.is_trained = True
        
        # Save model
        self.save_model()
        
        metrics = {
            "accuracy": accuracy,
            "classification_report": class_report,
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "feature_importance": dict(zip(feature_cols, self.model.feature_importances_))
        }
        
        logger.info(f"Model trained with accuracy: {accuracy:.3f}")
        return metrics
    
    def predict(self, features_df: pd.DataFrame) -> Tuple[List[str], List[float]]:
        """
        Predict threat levels for given features
        
        Args:
            features_df: DataFrame with extracted features
            
        Returns:
            Tuple of (predicted_labels, confidence_scores)
        """
        if not self.is_trained or self.model is None:
            logger.error("Model not trained. Cannot make predictions.")
            return [], []
        
        if features_df.empty:
            logger.warning("No features provided for prediction")
            return [], []
        
        # Prepare features
        if self.feature_columns is None:
            self.feature_columns = self._get_feature_columns(features_df)
        
        X = features_df[self.feature_columns].fillna(0)
        X_scaled = self.scaler.transform(X)
        
        # Make predictions
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        # Convert to labels
        predicted_labels = [self.class_labels[pred] for pred in predictions]
        confidence_scores = [float(max(prob)) for prob in probabilities]
        
        return predicted_labels, confidence_scores
    
    def predict_single(self, features: Dict[str, Any]) -> Tuple[str, float]:
        """
        Predict threat level for a single session
        
        Args:
            features: Dictionary of extracted features
            
        Returns:
            Tuple of (predicted_label, confidence_score)
        """
        # Convert to DataFrame
        df = pd.DataFrame([features])
        labels, confidences = self.predict(df)
        
        if labels and confidences:
            return labels[0], confidences[0]
        else:
            return 'amateur', 0.5  # Default fallback
    
    def _generate_synthetic_labels(self, features_df: pd.DataFrame) -> List[str]:
        """
        Generate synthetic labels based on feature heuristics
        This is used for initial training when no ground truth is available
        """
        labels = []
        
        for _, row in features_df.iterrows():
            # Heuristic-based labeling
            threat_score = row.get('threat_score', 0)
            suspicious_ratio = row.get('suspicious_ratio', 0)
            session_duration = row.get('session_duration', 0)
            command_count = row.get('command_count', 0)
            suspicious_commands = row.get('suspicious_commands', 0)
            
            # Classification logic - more specific thresholds
            if (threat_score < 1 and suspicious_ratio < 0.1 and 
                suspicious_commands == 0 and command_count <= 5):
                labels.append('scanner')
            elif (threat_score > 3 or suspicious_ratio > 0.2 or 
                  suspicious_commands > 2 or command_count > 8):
                labels.append('advanced')
            else:
                labels.append('amateur')
        
        return labels
    
    def _encode_labels(self, labels: List[str]) -> np.ndarray:
        """Encode string labels to numeric values"""
        label_map = {label: idx for idx, label in enumerate(self.class_labels)}
        return np.array([label_map[label] for label in labels])
    
    def _get_feature_columns(self, df: pd.DataFrame) -> List[str]:
        """Get available feature columns from dataframe"""
        # Define expected feature columns
        expected_features = [
            'session_duration', 'command_count', 'unique_commands',
            'failed_logins', 'successful_logins', 'login_success_rate',
            'suspicious_commands', 'scanner_commands', 'command_diversity',
            'commands_per_minute', 'suspicious_ratio', 'scanner_ratio',
            'is_high_activity', 'is_suspicious_heavy', 'is_scanner_heavy',
            'is_long_session', 'threat_score'
        ]
        
        # Return only columns that exist in the dataframe
        return [col for col in expected_features if col in df.columns]
    
    def save_model(self):
        """Save trained model and scaler to disk"""
        if self.model is None:
            logger.warning("No model to save")
            return
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns,
            'class_labels': self.class_labels,
            'is_trained': self.is_trained
        }
        
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(model_data, f)
            logger.info(f"Model saved to {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def load_model(self):
        """Load trained model and scaler from disk"""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_columns = model_data['feature_columns']
            self.class_labels = model_data['class_labels']
            self.is_trained = model_data['is_trained']
            
            logger.info(f"Model loaded from {self.model_path}")
        except FileNotFoundError:
            logger.info("No existing model found. Will train new model.")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model"""
        if not self.is_trained:
            return {"status": "not_trained"}
        
        return {
            "status": "trained",
            "model_type": "XGBoost",
            "feature_count": len(self.feature_columns) if self.feature_columns else 0,
            "class_labels": self.class_labels,
            "feature_importance": dict(zip(
                self.feature_columns, 
                self.model.feature_importances_
            )) if self.model else {}
        }
    
    def retrain_with_feedback(self, features_df: pd.DataFrame, 
                            correct_labels: List[str]) -> Dict[str, Any]:
        """
        Retrain model with corrected labels (for continuous learning)
        
        Args:
            features_df: DataFrame with features
            correct_labels: Corrected labels for the features
            
        Returns:
            Retraining metrics
        """
        logger.info("Retraining model with feedback")
        
        # Combine with existing training data if available
        # For now, just retrain with new data
        return self.train(features_df, correct_labels)