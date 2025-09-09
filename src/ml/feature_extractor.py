"""
Feature Extractor for ML-Powered Honeypot
Extracts behavioral features from Cowrie honeypot logs for threat classification
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)

class FeatureExtractor:
    """Extracts behavioral features from honeypot session logs"""
    
    def __init__(self):
        # Suspicious command patterns that indicate advanced attackers
        self.suspicious_commands = {
            'wget', 'curl', 'nc', 'netcat', 'nmap', 'masscan', 'zmap',
            'ssh', 'scp', 'rsync', 'tar', 'gzip', 'unzip', 'base64',
            'python', 'perl', 'bash', 'sh', 'chmod', 'chown', 'su',
            'sudo', 'passwd', 'useradd', 'usermod', 'crontab', 'at',
            'iptables', 'ufw', 'systemctl', 'service', 'ps', 'top',
            'kill', 'killall', 'pkill', 'nohup', 'screen', 'tmux'
        }
        
        # Common scanner commands (low threat)
        self.scanner_commands = {
            'ls', 'pwd', 'whoami', 'id', 'uname', 'cat', 'more', 'less',
            'head', 'tail', 'grep', 'find', 'which', 'whereis', 'locate'
        }
    
    def extract_session_features(self, session_logs: List[Dict]) -> Dict[str, Any]:
        """
        Extract features from a single session's logs
        
        Args:
            session_logs: List of log entries for a session
            
        Returns:
            Dictionary of extracted features
        """
        if not session_logs:
            return self._get_empty_features()
        
        # Basic session information
        session_id = session_logs[0].get('session', 'unknown')
        start_time = self._parse_timestamp(session_logs[0].get('timestamp'))
        end_time = self._parse_timestamp(session_logs[-1].get('timestamp'))
        
        # Calculate session duration
        session_duration = 0
        if start_time and end_time:
            session_duration = (end_time - start_time).total_seconds()
        
        # Extract commands and login attempts
        commands = []
        failed_logins = 0
        successful_logins = 0
        
        for log_entry in session_logs:
            event_type = log_entry.get('eventid', '')
            
            if event_type == 'cowrie.command.input':
                command = log_entry.get('input', '').strip()
                if command:
                    commands.append(command)
            
            elif event_type == 'cowrie.login.failed':
                failed_logins += 1
            
            elif event_type == 'cowrie.login.success':
                successful_logins += 1
        
        # Calculate derived features
        unique_commands = len(set(commands))
        command_count = len(commands)
        
        # Categorize commands
        suspicious_count = sum(1 for cmd in commands if any(sus in cmd.lower() for sus in self.suspicious_commands))
        scanner_count = sum(1 for cmd in commands if any(scan in cmd.lower() for scan in self.scanner_commands))
        
        # Calculate command diversity (entropy-like measure)
        command_diversity = self._calculate_diversity(commands)
        
        # Login success rate
        total_login_attempts = failed_logins + successful_logins
        login_success_rate = successful_logins / total_login_attempts if total_login_attempts > 0 else 0
        
        # Time-based features
        commands_per_minute = command_count / (session_duration / 60) if session_duration > 0 else 0
        
        features = {
            'session_id': session_id,
            'session_duration': session_duration,
            'command_count': command_count,
            'unique_commands': unique_commands,
            'failed_logins': failed_logins,
            'successful_logins': successful_logins,
            'login_success_rate': login_success_rate,
            'suspicious_commands': suspicious_count,
            'scanner_commands': scanner_count,
            'command_diversity': command_diversity,
            'commands_per_minute': commands_per_minute,
            'suspicious_ratio': suspicious_count / command_count if command_count > 0 else 0,
            'scanner_ratio': scanner_count / command_count if command_count > 0 else 0
        }
        
        return features
    
    def extract_batch_features(self, all_logs: List[Dict]) -> pd.DataFrame:
        """
        Extract features from multiple sessions
        
        Args:
            all_logs: List of all log entries
            
        Returns:
            DataFrame with extracted features
        """
        # Group logs by session
        sessions = {}
        for log_entry in all_logs:
            session_id = log_entry.get('session', 'unknown')
            if session_id not in sessions:
                sessions[session_id] = []
            sessions[session_id].append(log_entry)
        
        # Extract features for each session
        features_list = []
        for session_id, session_logs in sessions.items():
            features = self.extract_session_features(session_logs)
            features_list.append(features)
        
        if not features_list:
            return pd.DataFrame()
        
        df = pd.DataFrame(features_list)
        
        # Add derived features
        df = self._add_derived_features(df)
        
        return df
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string to datetime object"""
        if not timestamp_str:
            return None
        
        try:
            # Handle different timestamp formats
            if 'T' in timestamp_str:
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            logger.warning(f"Could not parse timestamp: {timestamp_str}")
            return None
    
    def _calculate_diversity(self, commands: List[str]) -> float:
        """Calculate command diversity using Shannon entropy"""
        if not commands:
            return 0.0
        
        # Count command frequencies
        command_counts = {}
        for cmd in commands:
            # Normalize command (take first word)
            base_cmd = cmd.split()[0].lower() if cmd.split() else cmd.lower()
            command_counts[base_cmd] = command_counts.get(base_cmd, 0) + 1
        
        # Calculate entropy
        total_commands = len(commands)
        entropy = 0.0
        
        for count in command_counts.values():
            probability = count / total_commands
            if probability > 0:
                entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _add_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add derived features to the dataframe"""
        if df.empty:
            return df
        
        # Threat level indicators
        df['is_high_activity'] = (df['commands_per_minute'] > 10).astype(int)
        df['is_suspicious_heavy'] = (df['suspicious_ratio'] > 0.3).astype(int)
        df['is_scanner_heavy'] = (df['scanner_ratio'] > 0.7).astype(int)
        df['is_long_session'] = (df['session_duration'] > 300).astype(int)  # 5 minutes
        
        # Combined threat score (simple heuristic)
        df['threat_score'] = (
            df['suspicious_commands'] * 2 +
            df['is_high_activity'] * 1 +
            df['is_long_session'] * 1 +
            df['failed_logins'] * 0.5
        )
        
        return df
    
    def _get_empty_features(self) -> Dict[str, Any]:
        """Return empty feature set for sessions with no data"""
        return {
            'session_id': 'unknown',
            'session_duration': 0,
            'command_count': 0,
            'unique_commands': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'login_success_rate': 0,
            'suspicious_commands': 0,
            'scanner_commands': 0,
            'command_diversity': 0,
            'commands_per_minute': 0,
            'suspicious_ratio': 0,
            'scanner_ratio': 0,
            'is_high_activity': 0,
            'is_suspicious_heavy': 0,
            'is_scanner_heavy': 0,
            'is_long_session': 0,
            'threat_score': 0
        }
    
    def get_feature_columns(self) -> List[str]:
        """Return list of feature column names for ML model"""
        return [
            'session_duration', 'command_count', 'unique_commands',
            'failed_logins', 'successful_logins', 'login_success_rate',
            'suspicious_commands', 'scanner_commands', 'command_diversity',
            'commands_per_minute', 'suspicious_ratio', 'scanner_ratio',
            'is_high_activity', 'is_suspicious_heavy', 'is_scanner_heavy',
            'is_long_session', 'threat_score'
        ]
