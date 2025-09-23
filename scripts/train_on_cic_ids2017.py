"""
Train XGBoost model on CIC-IDS2017 dataset
"""

import os
import sys
import json
import joblib
import logging
import numpy as np
import pandas as pd
import xgboost as xgb
from pathlib import Path
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, 
    f1_score, confusion_matrix, classification_report,
    roc_auc_score, average_precision_score
)
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Constants
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data/cic-ids2017/processed"
MODEL_DIR = BASE_DIR / "models"
CONFIG_FILE = BASE_DIR / "configs/ml_config.yaml"

# Create model directory if it doesn't exist
MODEL_DIR.mkdir(parents=True, exist_ok=True)

class CICIDS2017Trainer:
    """Train and evaluate XGBoost model on CIC-IDS2017 dataset."""
    
    def __init__(self, config_path=CONFIG_FILE):
        """Initialize the trainer with configuration."""
        self.config = self._load_config(config_path)
        self.model = None
        self.feature_importance = None
        self.metrics = {}
        
        # Set up model parameters
        self.params = self.config.get('model_params', {
            'objective': 'binary:logistic',
            'eval_metric': 'logloss',
            'use_label_encoder': False,
            'n_estimators': 100,
            'max_depth': 6,
            'learning_rate': 0.1,
            'subsample': 0.8,
            'colsample_bytree': 0.8,
            'random_state': 42,
            'n_jobs': -1
        })
        
        # Set up file paths
        self.train_file = DATA_DIR / "train.csv"
        self.test_file = DATA_DIR / "test.csv"
        self.model_file = MODEL_DIR / "xgb_cic_ids2017.model"
        self.metrics_file = MODEL_DIR / "training_metrics.json"
        
    def _load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Error loading config file: {e}. Using default parameters.")
            return {}
    
    def load_data(self):
        """Load and prepare training and test data."""
        logger.info("Loading training and test data...")
        
        # Load data
        train_data = pd.read_csv(self.train_file)
        test_data = pd.read_csv(self.test_file)
        
        # Separate features and target
        X_train = train_data.drop('target', axis=1)
        y_train = train_data['target']
        
        X_test = test_data.drop('target', axis=1)
        y_test = test_data['target']
        
        logger.info(f"Training data shape: {X_train.shape}")
        logger.info(f"Test data shape: {X_test.shape}")
        
        # Save feature columns for later use
        self.feature_columns = X_train.columns.tolist()
        with open(MODEL_DIR / 'feature_columns.json', 'w') as f:
            json.dump(self.feature_columns, f)
        
        return X_train, X_test, y_train, y_test
    
    def train_model(self, X_train, y_train, X_test, y_test):
        """Train the XGBoost model with early stopping."""
        logger.info("Training XGBoost model...")
        
        # Create DMatrix for XGBoost
        dtrain = xgb.DMatrix(X_train, label=y_train)
        dtest = xgb.DMatrix(X_test, label=y_test)
        
        # Define evaluation sets
        eval_set = [(dtrain, 'train'), (dtest, 'eval')]
        
        # Train model with early stopping
        self.model = xgb.train(
            params=self.params,
            dtrain=dtrain,
            num_boost_round=1000,
            evals=eval_set,
            early_stopping_rounds=20,
            verbose_eval=10
        )
        
        # Save feature importance
        self.feature_importance = self.model.get_score(importance_type='weight')
        
        # Save the model
        self.model.save_model(str(self.model_file))
        logger.info(f"Model saved to {self.model_file}")
        
        return self.model
    
    def evaluate_model(self, X_test, y_test):
        """Evaluate the model and calculate metrics."""
        if self.model is None:
            logger.error("Model not trained yet.")
            return
            
        logger.info("Evaluating model...")
        
        # Make predictions
        dtest = xgb.DMatrix(X_test)
        y_pred_proba = self.model.predict(dtest)
        y_pred = (y_pred_proba > 0.5).astype(int)
        
        # Calculate metrics
        self.metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted'),
            'recall': recall_score(y_test, y_pred, average='weighted'),
            'f1': f1_score(y_test, y_pred, average='weighted'),
            'roc_auc': roc_auc_score(y_test, y_pred_proba),
            'pr_auc': average_precision_score(y_test, y_pred_proba),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }
        
        # Log metrics
        logger.info(f"Accuracy: {self.metrics['accuracy']:.4f}")
        logger.info(f"Precision: {self.metrics['precision']:.4f}")
        logger.info(f"Recall: {self.metrics['recall']:.4f}")
        logger.info(f"F1 Score: {self.metrics['f1']:.4f}")
        logger.info(f"ROC AUC: {self.metrics['roc_auc']:.4f}")
        logger.info(f"PR AUC: {self.metrics['pr_auc']:.4f}")
        
        # Save metrics
        with open(self.metrics_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)
        
        # Plot confusion matrix
        self._plot_confusion_matrix(
            self.metrics['confusion_matrix'],
            ['Normal', 'Attack'],
            MODEL_DIR / 'confusion_matrix.png'
        )
        
        # Plot feature importance
        self._plot_feature_importance()
        
        return self.metrics
    
    def _plot_confusion_matrix(self, cm, classes, filename):
        """Plot and save confusion matrix."""
        plt.figure(figsize=(10, 8))
        sns.heatmap(
            cm, 
            annot=True, 
            fmt='d', 
            cmap='Blues',
            xticklabels=classes,
            yticklabels=classes
        )
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig(filename, bbox_inches='tight')
        plt.close()
        logger.info(f"Confusion matrix saved to {filename}")
    
    def _plot_feature_importance(self, top_n=20):
        """Plot and save feature importance."""
        if not self.feature_importance:
            return
            
        # Sort features by importance
        sorted_importance = sorted(
            self.feature_importance.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        # Get top N features
        top_features = dict(sorted_importance[:top_n])
        
        # Plot
        plt.figure(figsize=(12, 8))
        sns.barplot(
            x=list(top_features.values()),
            y=list(top_features.keys())
        )
        plt.title(f'Top {top_n} Important Features')
        plt.xlabel('Importance Score')
        plt.tight_layout()
        
        # Save plot
        plot_file = MODEL_DIR / 'feature_importance.png'
        plt.savefig(plot_file, bbox_inches='tight')
        plt.close()
        logger.info(f"Feature importance plot saved to {plot_file}")

def main():
    """Main function to run the training pipeline."""
    # Initialize trainer
    trainer = CICIDS2017Trainer()
    
    # Load data
    try:
        X_train, X_test, y_train, y_test = trainer.load_data()
    except Exception as e:
        logger.error(f"Error loading data: {e}")
        logger.info("Please run download_cic_ids2017.py first to download and preprocess the data.")
        return
    
    # Train model
    try:
        model = trainer.train_model(X_train, y_train, X_test, y_test)
    except Exception as e:
        logger.error(f"Error training model: {e}")
        return
    
    # Evaluate model
    try:
        metrics = trainer.evaluate_model(X_test, y_test)
        logger.info("\nModel training and evaluation completed successfully!")
        logger.info(f"Model saved to: {trainer.model_file}")
        logger.info(f"Metrics saved to: {trainer.metrics_file}")
    except Exception as e:
        logger.error(f"Error evaluating model: {e}")
        return

if __name__ == "__main__":
    main()
