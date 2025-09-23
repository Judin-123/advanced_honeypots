"""
ML-Powered Honeypot Main Application (Safe Mode)
Windows-compatible version with better error handling
"""

import time
import yaml
import logging
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any
import threading
import signal
import sys

# Import our modules
from src.ml.feature_extractor import FeatureExtractor
from src.ml.threat_classifier import ThreatClassifier
from src.adaptation.dynamic_adaptation import DynamicAdaptationEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/honeypot.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class MLHoneypotSafe:
    """Safe version of ML-powered honeypot for Windows/demo use"""
    
    def __init__(self, config_path: str = "configs/config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.running = False
        
        # Initialize components
        self.feature_extractor = FeatureExtractor()
        self.threat_classifier = ThreatClassifier(
            self.config.get("ml", {}).get("model_path", "models/threat_classifier.pkl")
        )
        self.adaptation_engine = DynamicAdaptationEngine(config_path)
        
        # Data storage
        self.recent_sessions = []
        self.session_buffer = []
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.stop()
    
    def start(self):
        """Start the ML-powered honeypot system"""
        logger.info("Starting ML-Powered Honeypot System (Safe Mode)")
        
        # Create necessary directories
        self._create_directories()
        
        # Initialize ML model if needed
        self._initialize_ml_model()
        
        # Start main processing loop
        self.running = True
        self._main_loop()
    
    def stop(self):
        """Stop the honeypot system"""
        logger.info("Stopping ML-Powered Honeypot System")
        self.running = False
    
    def _create_directories(self):
        """Create necessary directories"""
        directories = [
            "logs", "models", "data", "templates"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def _initialize_ml_model(self):
        """Initialize or train the ML model"""
        if not self.threat_classifier.is_trained:
            logger.info("Training initial ML model...")
            
            # Try to load existing training data
            training_data = self._load_training_data()
            
            if training_data:
                # Extract features and train model
                features_df = self.feature_extractor.extract_batch_features(training_data)
                if not features_df.empty:
                    metrics = self.threat_classifier.train(features_df)
                    logger.info(f"Model trained with accuracy: {metrics.get('accuracy', 'unknown')}")
                else:
                    logger.warning("No valid training data found")
            else:
                logger.info("No training data available, will train with synthetic data when sessions are available")
    
    def _load_training_data(self) -> List[Dict[str, Any]]:
        """Load existing training data from logs"""
        log_path = self.config.get("cowrie", {}).get("log_path", "/var/log/cowrie/cowrie.json")
        
        try:
            if os.path.exists(log_path):
                training_data = []
                with open(log_path, 'r') as f:
                    for line in f:
                        try:
                            log_entry = json.loads(line.strip())
                            training_data.append(log_entry)
                        except json.JSONDecodeError:
                            continue
                
                logger.info(f"Loaded {len(training_data)} log entries for training")
                return training_data
        except Exception as e:
            logger.error(f"Failed to load training data: {e}")
        
        return []
    
    def _main_loop(self):
        """Main processing loop"""
        check_interval = self.config.get("adaptation", {}).get("check_interval", 60)
        
        logger.info(f"Starting main loop with {check_interval}s intervals")
        logger.info("System running in safe mode - no external dependencies required")
        logger.info("Press Ctrl+C to stop")
        
        while self.running:
            try:
                # Collect new session data
                new_sessions = self._collect_new_sessions()
                
                if new_sessions:
                    logger.info(f"Collected {len(new_sessions)} new sessions")
                    
                    # Extract features
                    features_df = self.feature_extractor.extract_batch_features(new_sessions)
                    
                    if not features_df.empty:
                        # Make threat predictions
                        threat_predictions = self._classify_threats(features_df)
                        
                        # Update session buffer
                        self._update_session_buffer(features_df, threat_predictions)
                        
                        # Check if adaptation is needed
                        if self._should_adapt():
                            self._perform_adaptation()
                else:
                    logger.info("No new sessions found - system monitoring...")
                
                # Wait for next check
                time.sleep(check_interval)
                
            except Exception as e:
                logger.error(f"Error in main loop: {e}")
                time.sleep(check_interval)
    
    def _collect_new_sessions(self) -> List[Dict[str, Any]]:
        """Collect new session data from Cowrie logs"""
        log_path = self.config.get("cowrie", {}).get("log_path", "/var/log/cowrie/cowrie.json")
        new_sessions = []
        
        try:
            if os.path.exists(log_path):
                # Read new log entries since last check
                with open(log_path, 'r') as f:
                    lines = f.readlines()
                
                # Process new lines (simplified - in production, you'd track file position)
                for line in lines[-100:]:  # Process last 100 lines
                    try:
                        log_entry = json.loads(line.strip())
                        new_sessions.append(log_entry)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Failed to collect new sessions: {e}")
        
        return new_sessions
    
    def _classify_threats(self, features_df) -> List[tuple]:
        """Classify threats using ML model"""
        try:
            if not self.threat_classifier.is_trained:
                logger.warning("Model not trained, using heuristic classification")
                return self._heuristic_classification(features_df)
            
            predictions, confidences = self.threat_classifier.predict(features_df)
            return list(zip(predictions, confidences))
        
        except Exception as e:
            logger.error(f"Failed to classify threats: {e}")
            return []
    
    def _heuristic_classification(self, features_df) -> List[tuple]:
        """Fallback heuristic classification when ML model is not available"""
        predictions = []
        
        for _, row in features_df.iterrows():
            threat_score = row.get('threat_score', 0)
            suspicious_ratio = row.get('suspicious_ratio', 0)
            
            if threat_score < 2 and suspicious_ratio < 0.1:
                predictions.append(('scanner', 0.8))
            elif threat_score > 5 or suspicious_ratio > 0.3:
                predictions.append(('advanced', 0.8))
            else:
                predictions.append(('amateur', 0.8))
        
        return predictions
    
    def _update_session_buffer(self, features_df, threat_predictions):
        """Update the session buffer with new data"""
        for i, (_, row) in enumerate(features_df.iterrows()):
            if i < len(threat_predictions):
                threat_level, confidence = threat_predictions[i]
                
                session_data = {
                    'timestamp': datetime.now().isoformat(),
                    'session_id': row.get('session_id', 'unknown'),
                    'features': row.to_dict(),
                    'threat_level': threat_level,
                    'confidence': confidence
                }
                
                self.session_buffer.append(session_data)
        
        # Keep only recent sessions (last 100)
        self.session_buffer = self.session_buffer[-100:]
    
    def _should_adapt(self) -> bool:
        """Determine if adaptation should be performed"""
        min_sessions = self.config.get("adaptation", {}).get("min_sessions", 5)
        return len(self.session_buffer) >= min_sessions
    
    def _perform_adaptation(self):
        """Perform dynamic adaptation based on recent sessions"""
        try:
            # Get recent sessions and predictions
            recent_sessions = [s['features'] for s in self.session_buffer[-20:]]  # Last 20 sessions
            threat_predictions = [(s['threat_level'], s['confidence']) for s in self.session_buffer[-20:]]
            
            # Perform adaptation
            result = self.adaptation_engine.analyze_and_adapt(recent_sessions, threat_predictions)
            
            if result.get('status') == 'adapted':
                logger.info(f"Adaptation performed: {result['old_profile']} → {result['new_profile']}")
                logger.info(f"Reason: {result.get('reason', 'No reason provided')}")
            elif result.get('status') == 'no_change':
                logger.info(f"No adaptation needed - current profile: {result.get('current_profile')}")
            
        except Exception as e:
            logger.error(f"Failed to perform adaptation: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current system status"""
        return {
            "running": self.running,
            "sessions_processed": len(self.session_buffer),
            "model_trained": self.threat_classifier.is_trained,
            "current_profile": self.adaptation_engine.current_profile,
            "adaptation_count": len(self.adaptation_engine.adaptation_history)
        }

def main():
    """Main entry point"""
    try:
        # Create and start the honeypot
        honeypot = MLHoneypotSafe()
        honeypot.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

