# ML-Powered Honeypot Docker Setup
FROM ubuntu:20.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    openjdk-11-jdk \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Create application directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip3 install -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs models data templates

# Create cowrie user
RUN useradd -m -s /bin/bash cowrie

# Install and configure Cowrie
RUN git clone https://github.com/cowrie/cowrie.git /opt/cowrie && \
    chown -R cowrie:cowrie /opt/cowrie && \
    sudo -u cowrie python3 -m venv /opt/cowrie/cowrie-env && \
    sudo -u cowrie /opt/cowrie/cowrie-env/bin/pip install -r /opt/cowrie/requirements.txt

# Install Elasticsearch
RUN wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add - && \
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list && \
    apt-get update && \
    apt-get install -y elasticsearch && \
    rm -rf /var/lib/apt/lists/*

# Configure Elasticsearch
RUN echo "cluster.name: honeypot-cluster" >> /etc/elasticsearch/elasticsearch.yml && \
    echo "node.name: honeypot-node" >> /etc/elasticsearch/elasticsearch.yml && \
    echo "network.host: localhost" >> /etc/elasticsearch/elasticsearch.yml && \
    echo "http.port: 9200" >> /etc/elasticsearch/elasticsearch.yml && \
    echo "discovery.type: single-node" >> /etc/elasticsearch/elasticsearch.yml && \
    echo "xpack.security.enabled: false" >> /etc/elasticsearch/elasticsearch.yml

# Create log directories
RUN mkdir -p /var/log/cowrie && \
    chown cowrie:cowrie /var/log/cowrie

# Create supervisor configuration
RUN echo "[supervisord]" > /etc/supervisor/conf.d/honeypot.conf && \
    echo "nodaemon=true" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "[program:elasticsearch]" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "command=/usr/share/elasticsearch/bin/elasticsearch" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "user=elasticsearch" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "autostart=true" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "autorestart=true" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "[program:cowrie]" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "command=/opt/cowrie/cowrie-env/bin/python /opt/cowrie/bin/cowrie start" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "user=cowrie" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "directory=/opt/cowrie" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "autostart=true" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "autorestart=true" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "[program:ml-honeypot]" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "command=python3 main.py" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "directory=/app" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "autostart=true" >> /etc/supervisor/conf.d/honeypot.conf && \
    echo "autorestart=true" >> /etc/supervisor/conf.d/honeypot.conf

# Expose ports
EXPOSE 2222 5000 9200

# Start supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
