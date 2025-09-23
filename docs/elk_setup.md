# ELK Stack Setup for ML-Powered Honeypot

This guide explains how to set up and use the ELK (Elasticsearch, Logstash, Kibana) stack for monitoring and analyzing honeypot data.

## Prerequisites

- Docker and Docker Compose
- At least 8GB of RAM (16GB recommended)
- At least 20GB of free disk space

## Quick Start

1. **Start the ELK stack**:
   ```bash
   docker-compose up -d
   ```

2. **Generate sample data** (optional):
   ```bash
   python scripts/generate_sample_logs.py --send-to-logstash --num-entries 1000
   ```

3. **Set up the Kibana dashboard**:
   ```bash
   python scripts/setup_kibana_dashboard.py
   ```

4. **Access the dashboards**:
   - Kibana: http://localhost:5601
   - Elasticsearch: http://localhost:9200

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│             │    │             │    │             │    │             │
│  Honeypot   ├───►  Logstash   ├───►  Elastic-   ├───►   Kibana    │
│  (Port 2222)│    │  (Port 5000)│    │  search    │    │  (Port 5601)│
│             │    │             │    │  (Port 9200)│    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

## Configuration

### Logstash Pipeline

- **Input**: TCP/UDP 5000, File input from `/app/logs/honeypot.log`
- **Filters**:
  - Timestamp parsing
  - GeoIP lookup for source IPs
  - Threat level classification
  - Command parsing
- **Output**: Elasticsearch index `honeypot-*`

### Elasticsearch

- Single-node cluster
- Index template for honeypot data
- Automatic index management with rollover

### Kibana

- Pre-configured dashboards:
  - Overview: System health and activity summary
  - Threat Analysis: Attack patterns and sources
  - Command Analysis: Most executed commands
  - Geo Map: Attack origins

## Usage

### Sending Logs to Logstash

1. **From Python application**:
   ```python
   import socket
   import json
   
   def send_to_logstash(entry, host='localhost', port=5000):
       sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       sock.connect((host, port))
       sock.sendall((json.dumps(entry) + '\n').encode('utf-8'))
       sock.close()
   ```

2. **Using Filebeat** (recommended for production):
   ```yaml
   # filebeat.yml
   filebeat.inputs:
     - type: log
       paths:
         - /path/to/honeypot/logs/*.log
       json.keys_under_root: true
       json.add_error_key: true
   
   output.logstash:
     hosts: ["localhost:5000"]
   ```

### Generating Sample Data

```bash
# Generate 1000 sample log entries
python scripts/generate_sample_logs.py --num-entries 1000

# Send 500 entries directly to Logstash
python scripts/generate_sample_logs.py --send-to-logstash --num-entries 500
```

## Troubleshooting

### Common Issues

1. **Elasticsearch not starting**:
   - Check available memory (`docker stats`)
   - Increase Docker memory allocation
   - Try running with `ES_JAVA_OPTS="-Xms1g -Xmx1g"`

2. **Kibana not connecting to Elasticsearch**:
   - Verify Elasticsearch is running (`curl http://localhost:9200`)
   - Check for network connectivity between containers
   - Verify credentials in `docker-compose.yml`

3. **No data in Kibana**:
   - Check Logstash logs: `docker logs honeypot-logstash`
   - Verify index pattern exists in Kibana
  
### Viewing Logs

```bash
# View all container logs
docker-compose logs -f

# View specific service logs
docker logs honeypot-elasticsearch
docker logs honeypot-logstash
docker logs honeypot-kibana
```

## Security Considerations

1. **Change default credentials**:
   - Update `ELASTIC_PASSWORD` in `docker-compose.yml`
   - Enable security features in production

2. **Network security**:
   - Don't expose Elasticsearch or Kibana to the internet
   - Use a reverse proxy with authentication
   - Enable TLS for all communications

3. **Data retention**:
   - Configure ILM (Index Lifecycle Management) for automatic index rotation
   - Set up snapshot and restore for backups

## Next Steps

1. **Customize dashboards** in Kibana to match your needs
2. **Set up alerts** for suspicious activities
3. **Integrate with SIEM** for enterprise security monitoring
4. **Scale the stack** for production workloads

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
