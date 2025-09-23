"""
Setup Script for ML-Powered Honeypot
Initializes the project structure and environment
"""

import os
import sys
import shutil
from pathlib import Path
import logging
from typing import Dict, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('setup.log')
    ]
)
logger = logging.getLogger(__name__)

class ProjectSetup:
    """Handles project setup and directory structure creation"""
    
    def __init__(self, base_dir: Optional[str] = None):
        """Initialize with base directory"""
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).parent.parent
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load configuration from config file"""
        config_path = self.base_dir / "configs" / "ml_config.yaml"
        try:
            import yaml
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
            return {}
    
    def create_directory_structure(self) -> None:
        """Create the project directory structure"""
        directories = [
            # Data directories
            "data/raw",
            "data/processed",
            "data/external",
            "data/interim",
            
            # Models
            "models",
            "models/pretrained",
            "models/experiments",
            
            # Logs and outputs
            "logs",
            "logs/training",
            "logs/predictions",
            "logs/experiments",
            
            # Documentation
            "docs",
            "docs/source",
            "docs/build",
            
            # Tests
            "tests/unit",
            "tests/integration",
            "tests/data",
            
            # Source code
            "src/data",
            "src/features",
            "src/models",
            "src/visualization",
            "src/utils"
        ]
        
        # Create each directory
        for dir_path in directories:
            full_path = self.base_dir / dir_path
            full_path.mkdir(parents=True, exist_ok=True)
            (full_path / ".gitkeep").touch(exist_ok=True)
            logger.info(f"Created directory: {full_path}")
    
    def create_initial_files(self) -> None:
        """Create initial configuration and documentation files"""
        # Create README for data directory
        data_readme = self.base_dir / "data" / "README.md"
        if not data_readme.exists():
            data_readme.write_text(
                "# Data Directory\n\n"
                "This directory contains all data used in the ML-Powered Honeypot project.\n\n"
                "## Directory Structure\n"
                "- `raw/`: Raw data files, exactly as provided.\n"
                "- `processed/`: Cleaned and processed data ready for modeling.\n"
                "- `external/`: Data from third-party sources.\n"
                "- `interim/`: Intermediate data that has been transformed.\n"
                "## Data Sources\n"
                "1. **Synthetic Data**: Generated attack simulations\n"
                "2. **Real-world Data**: Collected from honeypot deployments\n"
                "## Usage\n\n"
                "```python\n"
                "# Example: Load processed data\n"
                "import pandas as pd\n"
                "df = pd.read_csv('data/processed/attack_data_processed.csv')\n"
                "```"
            )
        
        # Create .gitignore if it doesn't exist
        gitignore = self.base_dir / ".gitignore"
        if not gitignore.exists():
            gitignore.write_text(
                "# Python\n"
                "__pycache__/\n"
                "*.py[cod]\n"
                "*$py.class\n"
                "*.so\n"
                ".Python\n"
                "build/\n"
                "develop-eggs/\n"
                "dist/\n"
                "downloads/\n"
                "eggs/\n"
                ".eggs/\n"
                "lib/\n"
                "lib64/\n"
                "parts/\n"
                "sdist/\n"
                "var/\n"
                "wheels/\n"
                "*.egg-info/\n"
                ".installed.cfg\n"
                "*.egg\n"
                "\n# Data\n"
                "data/raw/\n"
                "data/processed/\n"
                "data/external/\n"
                "data/interim/\n"
                "\n# Models\n"
                "models/\n"
                "!models/README.md\n"
                "\n# Logs\n"
                "logs/\n"
                "*.log\n"
                "\n# Environment\n"
                ".env\n"
                ".venv\n"
                "env/\n"
                "venv/\n"
                "ENV/\n"
                "env.bak/\n"
                "venv.bak/\n"
                "\n# IDEs and editors\n"
                ".idea/\n"
                ".vscode/\n"
                "*.swp\n"
                "*.swo\n"
                "*~\n"
                "\n# Jupyter Notebook\n"
                ".ipynb_checkpoints\n"
                "*.ipynb\n"
                "\n# Local development\n"
                ".mypy_cache/\n"
                ".pytest_cache/\n"
                ".coverage\n"
                "htmlcov/"
            )
        
        # Create models README
        models_readme = self.base_dir / "models" / "README.md"
        if not models_readme.exists():
            models_readme.write_text(
                "# Models Directory\n\n"
                "This directory contains trained models and their configurations.\n\n"
                "## Directory Structure\n"
                "- `pretrained/`: Pre-trained models for immediate use\n"
                "- `experiments/`: Experimental models and results\n"
                "## Model Naming Convention\n"
                "Models should follow this naming convention:\n"
                "`<model_type>_<feature_set>_<date>_<version>.<extension>`\n\n"
                "Example: `xgboost_basic_features_20230901_v1.joblib`\n\n"
                "## Usage\n\n"
                "```python\n"
                "# Example: Load a trained model\n"
                "import joblib\n"
                "model = joblib.load('models/pretrained/xgboost_basic_features_20230901_v1.joblib')\n"
                "```"
            )
    
    def check_environment(self) -> Dict[str, bool]:
        """Check if the required environment is set up correctly"""
        results = {
            'python_version': self._check_python_version(),
            'dependencies': self._check_dependencies(),
            'environment_vars': self._check_environment_variables(),
            'write_permissions': self._check_write_permissions()
        }
        return results
    
    def _check_python_version(self) -> bool:
        """Check if Python version meets requirements"""
        import sys
        version_info = sys.version_info
        is_valid = version_info >= (3, 8)
        if not is_valid:
            logger.error(f"Python 3.8+ is required. Current version: {sys.version}")
        return is_valid
    
    def _check_dependencies(self) -> Dict[str, bool]:
        """Check if required Python packages are installed"""
        required_packages = [
            'numpy', 'pandas', 'scikit-learn', 'xgboost', 'joblib',
            'flask', 'pyyaml', 'matplotlib', 'seaborn'
        ]
        
        results = {}
        for pkg in required_packages:
            try:
                __import__(pkg)
                results[pkg] = True
            except ImportError:
                logger.warning(f"Missing dependency: {pkg}")
                results[pkg] = False
        
        return results
    
    def _check_environment_variables(self) -> Dict[str, bool]:
        """Check if required environment variables are set"""
        required_vars = [
            'PYTHONPATH',  # Should be set to the project root
        ]
        
        results = {}
        for var in required_vars:
            results[var] = var in os.environ
            if not results[var]:
                logger.warning(f"Environment variable not set: {var}")
        
        return results
    
    def _check_write_permissions(self) -> bool:
        """Check if we have write permissions in the project directory"""
        test_file = self.base_dir / ".write_test"
        try:
            with open(test_file, 'w') as f:
                f.write("test")
            test_file.unlink()
            return True
        except Exception as e:
            logger.error(f"No write permissions in {self.base_dir}: {e}")
            return False
    
    def setup_environment(self) -> None:
        """Set up the development environment"""
        logger.info("Setting up project environment...")
        
        # Create directory structure
        self.create_directory_structure()
        
        # Create initial files
        self.create_initial_files()
        
        # Check environment
        logger.info("Checking environment...")
        env_check = self.check_environment()
        
        # Print summary
        logger.info("\nSetup complete!")
        logger.info("\nEnvironment Check:")
        logger.info(f"- Python version: {'✓' if env_check['python_version'] else '✗'}")
        
        logger.info("\nDependencies:")
        for pkg, installed in env_check['dependencies'].items():
            logger.info(f"- {pkg}: {'✓' if installed else '✗'}")
        
        logger.info("\nEnvironment Variables:")
        for var, set_ in env_check['environment_vars'].items():
            logger.info(f"- {var}: {'✓' if set_ else '✗'}")
        
        logger.info("\nNext steps:")
        logger.info("1. Install dependencies: pip install -r requirements.txt")
        logger.info("2. Generate training data: python -m src.ml.data_collector")
        logger.info("3. Train the model: python -m src.ml.train")
        logger.info("4. Start the API: python -m src.api.app")

def main():
    """Main function to run the setup"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Setup the ML-Powered Honeypot project')
    parser.add_argument('--base-dir', type=str, help='Base directory for the project')
    
    args = parser.parse_args()
    
    setup = ProjectSetup(args.base_dir)
    setup.setup_environment()

if __name__ == "__main__":
    main()
