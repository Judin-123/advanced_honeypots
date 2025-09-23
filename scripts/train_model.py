"""
Model Training Pipeline for ML-Powered Honeypot

This script handles the complete training pipeline:
1. Data generation (if needed)
2. Data preprocessing
3. Model training
4. Model evaluation
5. Model persistence
"""

import os
import sys
import argparse
import logging
import json
import yaml
from pathlib import Path
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import xgboost as xgb
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, confusion_matrix, classification_report
)

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

# Import project modules
from src.ml.feature_extractor import FeatureExtractor
from src.ml.threat_classifier import ThreatClassifier

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
    """Handles the complete model training pipeline"""
    
    def __init__(self, config_path: str = "configs/ml_config.yaml"):
        """Initialize the model trainer with configuration"""
        self.config = self._load_config(config_path)
        self.feature_extractor = FeatureExtractor()
        self.model = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.feature_importances_ = None
        
        # Set up directories
        self._setup_directories()
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            raise
    
    def _setup_directories(self) -> None:
        """Create necessary directories"""
        dirs = [
            self.config.get('model_dir', 'models'),
            self.config.get('data', {}).get('processed_data_dir', 'data/processed'),
            'logs'
        ]
        
        for dir_path in dirs:
            os.makedirs(dir_path, exist_ok=True)
    
    def load_data(self, data_path: str = None) -> pd.DataFrame:
        """
        Load and preprocess the training data
        
        Args:
            data_path: Path to the data file. If None, use the path from config
            
        Returns:
            Processed DataFrame with features and labels
        """
        if data_path is None:
            data_path = self.config.get('data', {}).get('training_data')
        
        logger.info(f"Loading data from {data_path}")
        
        try:
            # Load the data
            df = pd.read_csv(data_path)
            
            # Extract features
            features = self.feature_extractor.extract_features(df)
            
            return features
            
        except Exception as e:
            logger.error(f"Error loading data: {e}")
            raise
    
    def prepare_data(self, data: pd.DataFrame) -> tuple:
        """
        Prepare data for training
        
        Args:
            data: DataFrame containing features and labels
            
        Returns:
            Tuple of (X_train, X_test, y_train, y_test)
        """
        # Separate features and target
        X = data.drop('threat_level', axis=1)
        y = data['threat_level']
        
        # Convert labels to numerical values
        label_mapping = {'scanner': 0, 'amateur': 1, 'advanced': 2}
        y = y.map(label_mapping)
        
        # Split data into train and test sets
        test_size = self.config.get('model', {}).get('test_size', 0.2)
        random_state = self.config.get('model', {}).get('random_state', 42)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=test_size,
            random_state=random_state,
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
        
        # Get model parameters from config
        params = self.config.get('model', {}).get('params', {
            'objective': 'multi:softmax',
            'num_class': 3,
            'max_depth': 6,
            'learning_rate': 0.1,
            'n_estimators': 100,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'random_state': 42,
            'eval_metric': 'mlogloss',
            'n_jobs': -1
        })
        
        # Initialize and train the model
        model = xgb.XGBClassifier(**params)
        
        # Fit the model
        model.fit(
            X_train, 
            y_train,
            eval_set=[(X_train, y_train)],
            verbose=True
        )
        
        # Store feature importances
        self.feature_importances_ = pd.DataFrame({
            'feature': X_train.columns,
            'importance': model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        return model
    
    def evaluate_model(self, model: xgb.XGBClassifier, 
                      X_test: pd.DataFrame, 
                      y_test: pd.Series) -> dict:
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
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1': f1_score(y_test, y_pred, average='weighted'),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }
        
        # Log metrics
        logger.info(f"Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"Precision: {metrics['precision']:.4f}")
        logger.info(f"Recall: {metrics['recall']:.4f}")
        logger.info(f"F1 Score: {metrics['f1']:.4f}")
        
        return metrics
    
    def save_model(self, model: xgb.XGBClassifier, metrics: dict) -> str:
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
        
        # Save feature importances
        if self.feature_importances_ is not None:
            self.feature_importances_.to_csv(model_dir / "feature_importances.csv", index=False)
        
        # Save metadata
        metadata = {
            'model_type': 'xgboost',
            'training_date': datetime.now().isoformat(),
            'feature_columns': list(self.X_train.columns) if self.X_train is not None else [],
            'metrics': metrics,
            'config': self.config.get('model', {})
        }
        
        with open(model_dir / "metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Model saved to {model_path}")
        return str(model_path)
    
    def run_pipeline(self, data_path: str = None) -> dict:
        """
        Run the complete training pipeline
        
        Args:
            data_path: Path to the training data file
            
        Returns:
            Dictionary containing training results
        """
        try:
            # Load and preprocess data
            data = self.load_data(data_path)
            
            # Prepare training and testing data
            self.X_train, self.X_test, self.y_train, self.y_test = self.prepare_data(data)
            
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

def generate_synthetic_data(output_path: str, num_samples: int = 10000) -> str:
    """
    Generate synthetic training data
    
    Args:
        output_path: Path to save the generated data
        num_samples: Number of samples to generate
        
    Returns:
        Path to the generated data file
    """
    from src.ml.data_collector import AttackSimulator
    
    logger.info(f"Generating {num_samples} synthetic attack samples...")
    
    # Initialize the attack simulator
    simulator = AttackSimulator()
    
    # Generate the dataset
    df = simulator.generate_dataset(num_samples)
    
    # Save to file
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    
    logger.info(f"Synthetic data saved to {output_path}")
    return str(output_path)

def main():
    """Main function to run the training pipeline"""
    parser = argparse.ArgumentParser(description='Train the ML-Powered Honeypot threat classifier')
    
    # Add arguments
    parser.add_argument('--config', type=str, default='configs/ml_config.yaml',
                      help='Path to configuration file')
    parser.add_argument('--data', type=str, 
                      help='Path to training data file')
    parser.add_argument('--generate-data', action='store_true',
                      help='Generate synthetic training data')
    parser.add_argument('--samples', type=int, default=10000,
                      help='Number of samples to generate (if --generate-data is used)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Generate data if requested
    if args.generate_data:
        output_path = args.data or 'data/raw/synthetic_attacks.csv'
        data_path = generate_synthetic_data(output_path, args.samples)
    else:
        data_path = args.data
    
    # Initialize and run the trainer
    trainer = ModelTrainer(args.config)
    results = trainer.run_pipeline(data_path)
    
    # Print results
    if results['status'] == 'success':
        print("\nTraining completed successfully!")
        print(f"Model saved to: {results['model_path']}")
        print(f"\nModel Performance:")
        print(f"- Accuracy: {results['metrics']['accuracy']:.4f}")
        print(f"- Precision: {results['metrics']['precision']:.4f}")
        print(f"- Recall: {results['metrics']['recall']:.4f}")
        print(f"- F1 Score: {results['metrics']['f1']:.4f}")
    else:
        print(f"\nTraining failed: {results.get('error', 'Unknown error')}")
        sys.exit(1)

if __name__ == "__main__":
    main()
