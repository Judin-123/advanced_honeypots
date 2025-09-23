"""
CIC-IDS2017 Dataset Download and Preprocessing Script
Downloads the CIC-IDS2017 dataset and prepares it for model training.
"""

import os
import sys
import gzip
import shutil
import pandas as pd
import numpy as np
from pathlib import Path
import urllib.request
from tqdm import tqdm
import logging
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
DATASET_URL = "https://www.unb.ca/cic/datasets/ids-2017/PCAPs/MachineLearningCSV.zip"
DATASET_DIR = Path("data/cic-ids2017")
PROCESSED_DIR = DATASET_DIR / "processed"
MODEL_DIR = Path("models")

# Create necessary directories
DATASET_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)

class CICIDS2017Processor:
    """Handles downloading and preprocessing of CIC-IDS2017 dataset."""
    
    def __init__(self):
        self.dataset_zip = DATASET_DIR / "MachineLearningCSV.zip"
        self.processed_train = PROCESSED_DIR / "train.csv"
        self.processed_test = PROCESSED_DIR / "test.csv"
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        
    def download_dataset(self):
        """Download the CIC-IDS2017 dataset."""
        if self.dataset_zip.exists():
            logger.info("Dataset already downloaded.")
            return True
            
        logger.info("Downloading CIC-IDS2017 dataset...")
        try:
            urllib.request.urlretrieve(
                DATASET_URL, 
                self.dataset_zip,
                self._download_progress
            )
            logger.info("\nDownload completed successfully!")
            return True
        except Exception as e:
            logger.error(f"Error downloading dataset: {e}")
            return False
    
    def _download_progress(self, block_num, block_size, total_size):
        """Show download progress."""
        downloaded = block_num * block_size
        percent = min(int(downloaded * 100 / total_size), 100)
        sys.stdout.write(f"\rDownloading... {percent}%")
        sys.stdout.flush()
    
    def extract_dataset(self):
        """Extract the downloaded dataset."""
        import zipfile
        
        if not self.dataset_zip.exists():
            logger.error("Dataset zip file not found. Please download it first.")
            return False
            
        extract_dir = DATASET_DIR / "extracted"
        extract_dir.mkdir(exist_ok=True)
        
        logger.info("Extracting dataset...")
        try:
            with zipfile.ZipFile(self.dataset_zip, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            logger.info("Extraction completed!")
            return True
        except Exception as e:
            logger.error(f"Error extracting dataset: {e}")
            return False
    
    def preprocess_data(self):
        """Preprocess the dataset for training."""
        if self.processed_train.exists() and self.processed_test.exists():
            logger.info("Processed data already exists. Loading...")
            return True
            
        extract_dir = DATASET_DIR / "extracted"
        csv_files = list(extract_dir.glob("*.csv"))
        
        if not csv_files:
            logger.error("No CSV files found in the extracted directory.")
            return False
            
        # Read and concatenate all CSV files
        logger.info("Reading and processing CSV files...")
        dfs = []
        for file in tqdm(csv_files, desc="Processing files"):
            try:
                df = pd.read_csv(file, low_memory=False)
                # Drop rows with infinite values
                df.replace([np.inf, -np.inf], np.nan, inplace=True)
                df.dropna(inplace=True)
                dfs.append(df)
            except Exception as e:
                logger.warning(f"Error processing {file.name}: {e}")
                continue
                
        if not dfs:
            logger.error("No valid data found in CSV files.")
            return False
            
        # Combine all data
        data = pd.concat(dfs, axis=0, ignore_index=True)
        
        # Clean column names
        data.columns = data.columns.str.strip()
        
        # Handle labels
        if 'Label' in data.columns:
            # Convert to binary classification (Normal vs Attack)
            data['is_attack'] = data['Label'].apply(lambda x: 0 if x.strip() == 'BENIGN' else 1)
            
            # Encode attack types
            self.label_encoder.fit(data['Label'])
            data['attack_type'] = self.label_encoder.transform(data['Label'])
            
            # Save label mapping
            label_mapping = dict(zip(
                self.label_encoder.classes_, 
                range(len(self.label_encoder.classes_))
            ))
            with open(MODEL_DIR / 'label_mapping.json', 'w') as f:
                json.dump(label_mapping, f, indent=2)
        
        # Select features and target
        feature_columns = [col for col in data.columns 
                         if col not in ['Label', 'is_attack', 'attack_type']]
        
        X = data[feature_columns]
        y = data['is_attack']  # Binary classification
        
        # Handle non-numeric columns
        for col in X.select_dtypes(include=['object']).columns:
            try:
                X[col] = pd.to_numeric(X[col], errors='coerce')
            except:
                # If conversion fails, drop the column
                X.drop(columns=[col], inplace=True)
        
        # Drop remaining non-numeric columns and fill NaN values
        X = X.select_dtypes(include=[np.number])
        X.fillna(0, inplace=True)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Save processed data
        train_df = pd.DataFrame(X_train, columns=X.columns)
        train_df['target'] = y_train.values
        train_df.to_csv(self.processed_train, index=False)
        
        test_df = pd.DataFrame(X_test, columns=X.columns)
        test_df['target'] = y_test.values
        test_df.to_csv(self.processed_test, index=False)
        
        # Save the scaler
        joblib.dump(self.scaler, MODEL_DIR / 'scaler.pkl')
        
        logger.info(f"Preprocessing complete. Processed data saved to {PROCESSED_DIR}")
        return True

def main():
    """Main function to run the data processing pipeline."""
    processor = CICIDS2017Processor()
    
    # Download dataset
    if not processor.download_dataset():
        return
        
    # Extract dataset
    if not processor.extract_dataset():
        return
        
    # Preprocess data
    if not processor.preprocess_data():
        return
        
    logger.info("Data processing completed successfully!")

if __name__ == "__main__":
    main()
