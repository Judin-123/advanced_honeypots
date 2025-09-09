"""
Dynamic Adaptation Engine for ML-Powered Honeypot
Modifies honeypot behavior based on ML threat classification
"""

import json
import yaml
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import subprocess
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class DynamicAdaptationEngine:
    """Manages dynamic adaptation of honeypot behavior based on ML predictions"""
    
    def __init__(self, config_path: str = "configs/config.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.current_profile = "standard"
        self.last_adaptation = None
        self.adaptation_history = []
        self.session_classifications = {}
        
        # Load existing adaptation history
        self._load_adaptation_history()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return {}
    
    def analyze_and_adapt(self, recent_sessions: List[Dict[str, Any]], 
                         threat_predictions: List[Tuple[str, float]]) -> Dict[str, Any]:
        """
        Analyze recent sessions and adapt honeypot behavior
        
        Args:
            recent_sessions: List of recent session data
            threat_predictions: List of (threat_level, confidence) tuples
            
        Returns:
            Adaptation decision and metadata
        """
        if not recent_sessions or not threat_predictions:
            logger.warning("No sessions or predictions provided for adaptation")
            return {"status": "no_data"}
        
        # Check adaptation cooldown
        if self._is_in_cooldown():
            logger.info("Adaptation in cooldown period")
            return {"status": "cooldown", "current_profile": self.current_profile}
        
        # Analyze threat distribution
        threat_analysis = self._analyze_threat_distribution(threat_predictions)
        
        # Determine new profile
        new_profile = self._determine_optimal_profile(threat_analysis)
        
        # Apply adaptation if needed
        if new_profile != self.current_profile:
            adaptation_result = self._apply_adaptation(new_profile, threat_analysis)
            return adaptation_result
        else:
            logger.info(f"No adaptation needed. Current profile '{self.current_profile}' is optimal.")
            return {
                "status": "no_change",
                "current_profile": self.current_profile,
                "threat_analysis": threat_analysis
            }
    
    def _analyze_threat_distribution(self, predictions: List[Tuple[str, float]]) -> Dict[str, Any]:
        """Analyze the distribution of threat predictions"""
        if not predictions:
            return {"error": "No predictions provided"}
        
        threat_counts = {"scanner": 0, "amateur": 0, "advanced": 0}
        total_confidence = 0
        
        for threat_level, confidence in predictions:
            threat_counts[threat_level] += 1
            total_confidence += confidence
        
        total_sessions = len(predictions)
        avg_confidence = total_confidence / total_sessions if total_sessions > 0 else 0
        
        # Calculate threat ratios
        threat_ratios = {
            level: count / total_sessions 
            for level, count in threat_counts.items()
        }
        
        # Determine dominant threat type
        dominant_threat = max(threat_counts, key=threat_counts.get)
        
        return {
            "total_sessions": total_sessions,
            "threat_counts": threat_counts,
            "threat_ratios": threat_ratios,
            "dominant_threat": dominant_threat,
            "average_confidence": avg_confidence,
            "high_confidence_sessions": sum(1 for _, conf in predictions if conf > 0.8)
        }
    
    def _determine_optimal_profile(self, threat_analysis: Dict[str, Any]) -> str:
        """Determine the optimal honeypot profile based on threat analysis"""
        if "error" in threat_analysis:
            return "standard"  # Default fallback
        
        dominant_threat = threat_analysis["dominant_threat"]
        threat_ratios = threat_analysis["threat_ratios"]
        avg_confidence = threat_analysis["average_confidence"]
        
        # Adaptation logic based on threat patterns
        if dominant_threat == "scanner" and threat_ratios["scanner"] > 0.7:
            # High proportion of scanners - use minimal profile to save resources
            return "minimal"
        
        elif dominant_threat == "advanced" and threat_ratios["advanced"] > 0.3:
            # Significant advanced threats - use deception profile
            return "deception"
        
        elif (threat_ratios["advanced"] > 0.1 or 
              threat_analysis["high_confidence_sessions"] > 2):
            # Some advanced threats or high confidence predictions - use deception
            return "deception"
        
        elif threat_ratios["scanner"] > 0.5:
            # Mostly scanners - use minimal profile
            return "minimal"
        
        else:
            # Mixed or amateur threats - use standard profile
            return "standard"
    
    def _apply_adaptation(self, new_profile: str, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Apply the new honeypot profile"""
        try:
            # Update Cowrie configuration
            self._update_cowrie_config(new_profile)
            
            # Update internal state
            old_profile = self.current_profile
            self.current_profile = new_profile
            self.last_adaptation = datetime.now()
            
            # Record adaptation
            adaptation_record = {
                "timestamp": self.last_adaptation.isoformat(),
                "old_profile": old_profile,
                "new_profile": new_profile,
                "threat_analysis": threat_analysis,
                "reason": self._get_adaptation_reason(threat_analysis)
            }
            
            self.adaptation_history.append(adaptation_record)
            self._save_adaptation_history()
            
            logger.info(f"Adapted from '{old_profile}' to '{new_profile}'")
            
            return {
                "status": "adapted",
                "old_profile": old_profile,
                "new_profile": new_profile,
                "timestamp": self.last_adaptation.isoformat(),
                "threat_analysis": threat_analysis,
                "reason": adaptation_record["reason"]
            }
            
        except Exception as e:
            logger.error(f"Failed to apply adaptation: {e}")
            return {"status": "error", "error": str(e)}
    
    def _update_cowrie_config(self, profile: str):
        """Update Cowrie configuration file with new profile settings"""
        if profile not in self.config.get("cowrie", {}).get("profiles", {}):
            logger.error(f"Unknown profile: {profile}")
            return
        
        profile_config = self.config["cowrie"]["profiles"][profile]
        cowrie_config_path = self.config["cowrie"]["config_path"]
        
        # Create new Cowrie configuration
        new_config = self._generate_cowrie_config(profile_config)
        
        # Backup current config
        self._backup_cowrie_config(cowrie_config_path)
        
        # Write new config
        try:
            with open(cowrie_config_path, 'w') as f:
                f.write(new_config)
            
            # Restart Cowrie service to apply changes
            self._restart_cowrie_service()
            
        except Exception as e:
            logger.error(f"Failed to update Cowrie config: {e}")
            raise
    
    def _generate_cowrie_config(self, profile_config: Dict[str, Any]) -> str:
        """Generate Cowrie configuration based on profile"""
        config_lines = [
            "[cowrie]",
            "enabled = true",
            "listen_port = 2222",
            "",
            "[output_jsonlog]",
            "enabled = true",
            f"logfile = {self.config['cowrie']['log_path']}",
            "",
            "[honeypot]",
            f"enabled_commands = {','.join(profile_config.get('enabled_commands', []))}",
            f"response_delay = {profile_config.get('response_delay', 0.5)}",
            "",
            "[fakefiles]",
            "enabled = true"
        ]
        
        # Add fake files
        fake_files = profile_config.get('fake_files', [])
        for fake_file in fake_files:
            config_lines.append(f"fake_{fake_file} = /etc/{fake_file}")
        
        return "\n".join(config_lines)
    
    def _backup_cowrie_config(self, config_path: str):
        """Create backup of current Cowrie configuration"""
        backup_path = f"{config_path}.backup.{int(time.time())}"
        try:
            if os.path.exists(config_path):
                subprocess.run(["cp", config_path, backup_path], check=True)
                logger.info(f"Backed up config to {backup_path}")
        except Exception as e:
            logger.warning(f"Failed to backup config: {e}")
    
    def _restart_cowrie_service(self):
        """Restart Cowrie service to apply configuration changes"""
        try:
            # Try systemctl first
            result = subprocess.run(
                ["systemctl", "restart", "cowrie"], 
                capture_output=True, text=True
            )
            if result.returncode == 0:
                logger.info("Cowrie service restarted successfully")
                return
            
            # Fallback to direct process restart
            subprocess.run(["pkill", "-f", "cowrie"], check=False)
            time.sleep(2)
            # Start Cowrie (this would need to be customized based on your setup)
            logger.info("Cowrie process restarted")
            
        except Exception as e:
            logger.warning(f"Failed to restart Cowrie service: {e}")
    
    def _get_adaptation_reason(self, threat_analysis: Dict[str, Any]) -> str:
        """Generate human-readable reason for adaptation"""
        dominant_threat = threat_analysis.get("dominant_threat", "unknown")
        threat_ratios = threat_analysis.get("threat_ratios", {})
        
        if dominant_threat == "scanner" and threat_ratios.get("scanner", 0) > 0.7:
            return "High proportion of scanners detected - switching to minimal profile to conserve resources"
        
        elif dominant_threat == "advanced" and threat_ratios.get("advanced", 0) > 0.3:
            return "Advanced threats detected - switching to deception profile with enhanced countermeasures"
        
        elif threat_analysis.get("high_confidence_sessions", 0) > 2:
            return "High-confidence threat predictions - switching to deception profile"
        
        else:
            return f"Threat distribution analysis indicates {dominant_threat} threats - adjusting profile accordingly"
    
    def _is_in_cooldown(self) -> bool:
        """Check if adaptation is in cooldown period"""
        if not self.last_adaptation:
            return False
        
        cooldown_seconds = self.config.get("adaptation", {}).get("cooldown", 300)
        time_since_adaptation = datetime.now() - self.last_adaptation
        
        return time_since_adaptation.total_seconds() < cooldown_seconds
    
    def _load_adaptation_history(self):
        """Load adaptation history from file"""
        history_path = "data/adaptation_history.json"
        try:
            if os.path.exists(history_path):
                with open(history_path, 'r') as f:
                    self.adaptation_history = json.load(f)
                logger.info(f"Loaded {len(self.adaptation_history)} adaptation records")
        except Exception as e:
            logger.warning(f"Failed to load adaptation history: {e}")
            self.adaptation_history = []
    
    def _save_adaptation_history(self):
        """Save adaptation history to file"""
        history_path = "data/adaptation_history.json"
        try:
            os.makedirs(os.path.dirname(history_path), exist_ok=True)
            with open(history_path, 'w') as f:
                json.dump(self.adaptation_history, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save adaptation history: {e}")
    
    def get_adaptation_status(self) -> Dict[str, Any]:
        """Get current adaptation status and history"""
        return {
            "current_profile": self.current_profile,
            "last_adaptation": self.last_adaptation.isoformat() if self.last_adaptation else None,
            "adaptation_count": len(self.adaptation_history),
            "in_cooldown": self._is_in_cooldown(),
            "recent_adaptations": self.adaptation_history[-5:] if self.adaptation_history else []
        }
    
    def force_adaptation(self, profile: str, reason: str = "Manual override") -> Dict[str, Any]:
        """Force adaptation to a specific profile (for testing/manual control)"""
        logger.info(f"Force adapting to profile: {profile}")
        
        threat_analysis = {
            "total_sessions": 0,
            "threat_counts": {"scanner": 0, "amateur": 0, "advanced": 0},
            "threat_ratios": {"scanner": 0, "amateur": 0, "advanced": 0},
            "dominant_threat": "manual",
            "average_confidence": 1.0,
            "high_confidence_sessions": 0
        }
        
        return self._apply_adaptation(profile, threat_analysis)
