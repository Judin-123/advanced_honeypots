"""
Script to download and prepare the CIC-IDS2017 dataset
"""
import os
import sys
import urllib.request
import zipfile
import pandas as pd
from pathlib import Path
import logging
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('download.log')
    ]
)
logger = logging.getLogger(__name__)

# Constants
DATASET_URL = "https://www.unb.ca/cic/datasets/ids-2017/PCAPs/MachineLearningCSV.zip"
DATASET_DIR = Path("data/cic-ids2017")
DATASET_ZIP = DATASET_DIR / "MachineLearningCSV.zip"
EXTRACT_DIR = DATASET_DIR / "extracted"
PROCESSED_DIR = DATASET_DIR / "processed"

# Create necessary directories
DATASET_DIR.mkdir(parents=True, exist_ok=True)
EXTRACT_DIR.mkdir(exist_ok=True)
PROCESSED_DIR.mkdir(exist_ok=True)

class DownloadProgressBar(tqdm):
    """Progress bar for downloads"""
    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)

def download_file(url: str, output_path: Path) -> bool:
    """Download a file with progress bar"""
    try:
        with DownloadProgressBar(unit='B', unit_scale=True, miniters=1, desc=url.split('/')[-1]) as t:
            urllib.request.urlretrieve(url, filename=output_path, reporthook=t.update_to)
        return True
    except Exception as e:
        logger.error(f"Error downloading {url}: {e}")
        return False

def extract_zip(zip_path: Path, extract_to: Path) -> bool:
    """Extract zip file"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        return True
    except Exception as e:
        logger.error(f"Error extracting {zip_path}: {e}")
        return False

def process_dataset():
    """Process the downloaded dataset"""
    # List of CSV files in the extracted directory
    csv_files = list(EXTRACT_DIR.glob("*.csv"))
    
    if not csv_files:
        logger.error("No CSV files found in the extracted directory.")
        return False
    
    # Process each CSV file
    all_data = []
    for csv_file in tqdm(csv_files, desc="Processing files"):
        try:
            # Read CSV file
            df = pd.read_csv(csv_file, low_memory=False)
            
            # Basic cleaning
            df = df.dropna()
            df = df[~df.isin([np.inf, -np.inf]).any(axis=1)]
            
            # Add filename as a column for reference
            df['source_file'] = csv_file.name
            
            all_data.append(df)
            logger.info(f"Processed {csv_file.name}: {len(df)} rows")
            
        except Exception as e:
            logger.error(f"Error processing {csv_file.name}: {e}")
    
    if not all_data:
        logger.error("No data was successfully processed.")
        return False
    
    # Combine all data
    combined_df = pd.concat(all_data, ignore_index=True)
    
    # Save processed data
    train_df = combined_df.sample(frac=0.8, random_state=42)
    test_df = combined_df.drop(train_df.index)
    
    train_df.to_csv(PROCESSED_DIR / "train.csv", index=False)
    test_df.to_csv(PROCESSED_DIR / "test.csv", index=False)
    
    logger.info(f"Training data saved: {len(train_df)} rows")
    logger.info(f"Test data saved: {len(test_df)} rows")
    
    return True

def main():
    """Main function to run the download and processing pipeline"""
    # Download the dataset if it doesn't exist
    if not DATASET_ZIP.exists():
        logger.info(f"Downloading dataset from {DATASET_URL}...")
        if not download_file(DATASET_URL, DATASET_ZIP):
            logger.error("Failed to download the dataset.")
            return False
    
    # Extract the dataset if not already extracted
    if not list(EXTRACT_DIR.glob("*.csv")):
        logger.info("Extracting dataset...")
        if not extract_zip(DATASET_ZIP, EXTRACT_DIR):
            logger.error("Failed to extract the dataset.")
            return False
    
    # Process the dataset
    logger.info("Processing dataset...")
    if not process_dataset():
        logger.error("Failed to process the dataset.")
        return False
    
    logger.info("Dataset download and processing completed successfully!")
    return True

if __name__ == "__main__":
    import numpy as np  # Required for NaN/inf handling
    success = main()
    sys.exit(0 if success else 1)
