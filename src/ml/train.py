"""
Model Training Script for ML-Powered Honeypot
Handles data collection, preprocessing, model training, and evaluation
"""

import os
import sys
import json
import yaml
import numpy as np
import pandas as pd
import xgboost as xgb
from datetime import datetime
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import logging
from typing import Dict, List, Tuple, Any, Optional

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))
from ml.feature_extractor import FeatureExtractor
from ml.threat_classifier import ThreatClassifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ModelTrainer:
    """Handles the end-to-end training pipeline for the threat classifier"""
    
    def __init__(self, config_path: str = "configs/config.yaml"):
        """Initialize the model trainer with configuration"""
        self.config = self._load_config(config_path)
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        
        # Create necessary directories
        self._setup_directories()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def _setup_directories(self) -> None:
        """Create necessary directories for models and data"""
        os.makedirs(self.config.get('model_dir', 'models'), exist_ok=True)
        os.makedirs(self.config.get('data_dir', 'data/processed'), exist_ok=True)
        os.makedirs(self.config.get('logs_dir', 'logs'), exist_ok=True)
    
    def load_data(self, data_path: Optional[str] = None) -> pd.DataFrame:
        """
        Load and preprocess the training data
        
        Args:
            data_path: Path to the raw data file. If None, use default from config
            
        Returns:
            pd.DataFrame: Processed DataFrame with features and labels
        """
        data_path = data_path or self.config.get('data', {}).get('training_data')
        if not data_path or not os.path.exists(data_path):
            raise FileNotFoundError(f"Training data not found at {data_path}")
        
        logger.info(f"Loading data from {data_path}")
        
        # Load and preprocess the data
        df = pd.read_csv(data_path)
        
        # Extract features
        features = self.feature_extractor.extract_features(df)
        
        return features
    
    def prepare_training_data(self, data: pd.DataFrame) -> Tuple:
        """
        Prepare training and testing data
        
        Args:
            data: DataFrame containing features and labels
            
        Returns:
            Tuple of (X_train, X_test, y_train, y_test)
        """
        # Separate features and target
        X = data.drop('threat_level', axis=1)
        y = data['threat_level']
        
        # Split data into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=self.config.get('training', {}).get('test_size', 0.2),
            random_state=42,
            stratify=y
        )
        
        return X_train, X_test, y_train, y_test
    
    def train_model(self, X_train: pd.DataFrame, y_train: pd.Series) -> xgb.XGBClassifier:
        """
        Train the XGBoost classifier
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            Trained XGBoost classifier
        """
        logger.info("Training XGBoost classifier...")
        
        # Get model parameters from config or use defaults
        params = self.config.get('model', {}).get('params', {
            'objective': 'multi:softmax',
            'num_class': 3,
            'max_depth': 6,
            'learning_rate': 0.1,
            'n_estimators': 100,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'random_state': 42,
            'eval_metric': 'mlogloss'
        })
        
        # Initialize and train the model
        model = xgb.XGBClassifier(**params)
        model.fit(
            X_train, 
            y_train,
            eval_set=[(X_train, y_train)],
            verbose=True
        )
        
        return model
    
    def evaluate_model(self, model: xgb.XGBClassifier, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
        """
        Evaluate the trained model
        
        Args:
            model: Trained XGBoost classifier
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary containing evaluation metrics
        """
        logger.info("Evaluating model...")
        
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True)
        conf_matrix = confusion_matrix(y_test, y_pred).tolist()
        
        # Log metrics
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info("Classification Report:")
        logger.info(classification_report(y_test, y_pred))
        
        return {
            'accuracy': accuracy,
            'classification_report': report,
            'confusion_matrix': conf_matrix,
            'timestamp': datetime.now().isoformat()
        }
    
    def save_model(self, model: xgb.XGBClassifier, metrics: Dict[str, Any]) -> str:
        """
        Save the trained model and metadata
        
        Args:
            model: Trained XGBoost classifier
            metrics: Dictionary of evaluation metrics
            
        Returns:
            Path to the saved model
        """
        # Create model directory with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        model_dir = Path(self.config.get('model_dir', 'models')) / f"model_{timestamp}"
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Save model
        model_path = model_dir / "model.joblib"
        joblib.dump(model, model_path)
        
        # Save metadata
        metadata = {
            'model_type': 'xgboost',
            'training_date': datetime.now().isoformat(),
            'feature_columns': list(self.X_train.columns) if self.X_train is not None [],
            'metrics': metrics,
            'config': self.config.get('model', {})
        }
        
        with open(model_dir / "metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Model saved to {model_path}")
        return str(model_path)
    
    def run_training_pipeline(self, data_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Run the complete training pipeline
        
        Args:
            data_path: Optional path to training data
            
        Returns:
            Dictionary containing training results and metrics
        """
        try:
            # Load and preprocess data
            logger.info("Starting training pipeline...")
            data = self.load_data(data_path)
            
            # Prepare training and testing data
            self.X_train, self.X_test, self.y_train, self.y_test = self.prepare_training_data(data)
            
            # Train the model
            model = self.train_model(self.X_train, self.y_train)
            
            # Evaluate the model
            metrics = self.evaluate_model(model, self.X_test, self.y_test)
            
            # Save the model
            model_path = self.save_model(model, metrics)
            
            return {
                'status': 'success',
                'model_path': model_path,
                'metrics': metrics
            }
            
        except Exception as e:
            logger.error(f"Training pipeline failed: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }

def main():
    """Main function to run the training pipeline"""
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Train the ML-Powered Honeypot threat classifier')
    parser.add_argument('--config', type=str, default='configs/config.yaml',
                      help='Path to configuration file')
    parser.add_argument('--data', type=str, 
                      help='Path to training data file')
    
    args = parser.parse_args()
    
    # Initialize and run the trainer
    trainer = ModelTrainer(args.config)
    results = trainer.run_training_pipeline(args.data)
    
    if results['status'] == 'success':
        print(f"\nTraining completed successfully!")
        print(f"Model saved to: {results['model_path']}")
        print(f"Accuracy: {results['metrics']['accuracy']:.4f}")
    else:
        print(f"\nTraining failed: {results.get('error', 'Unknown error')}")
        sys.exit(1)

if __name__ == "__main__":
    main()
