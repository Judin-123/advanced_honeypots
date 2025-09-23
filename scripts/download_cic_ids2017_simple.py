"""
Simple script to download CIC-IDS2017 dataset
"""
import os
import sys
import urllib.request
from pathlib import Path
import zipfile

def download_file(url, destination):
    """Download a file with progress bar"""
    def progress_hook(count, block_size, total_size):
        progress = min(int(count * block_size * 100 / total_size), 100)
        sys.stdout.write(f"\rDownloading... {progress}%")
        sys.stdout.flush()
    
    print(f"Downloading {url} to {destination}")
    try:
        urllib.request.urlretrieve(url, destination, progress_hook)
        print("\nDownload completed!")
        return True
    except Exception as e:
        print(f"\nError downloading file: {e}")
        return False

def extract_zip(zip_path, extract_to):
    """Extract zip file"""
    print(f"Extracting {zip_path} to {extract_to}")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        print("Extraction completed!")
        return True
    except Exception as e:
        print(f"Error extracting file: {e}")
        return False

def main():
    # Configuration
    DATASET_URL = "https://www.unb.ca/cic/datasets/ids-2017/PCAPs/MachineLearningCSV.zip"
    DATASET_DIR = Path("data/cic-ids2017")
    EXTRACT_DIR = DATASET_DIR / "extracted"
    
    # Create directories
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT_DIR.mkdir(exist_ok=True)
    
    # Download the dataset
    zip_path = DATASET_DIR / "MachineLearningCSV.zip"
    if not zip_path.exists():
        if not download_file(DATASET_URL, zip_path):
            return
    
    # Extract the dataset
    if not list(EXTRACT_DIR.glob('*')):  # If directory is empty
        if not extract_zip(zip_path, EXTRACT_DIR):
            return
    
    print("\nDataset is ready at:")
    print(f"- Downloaded: {zip_path}")
    print(f"- Extracted:  {EXTRACT_DIR}")

if __name__ == "__main__":
    main()
