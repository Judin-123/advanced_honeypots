#!/usr/bin/env python3
"""
Setup Kibana Dashboard for ML-Powered Honeypot

This script creates index patterns, visualizations, and dashboards in Kibana
for monitoring and analyzing honeypot data.
"""

import json
import os
import time
import requests
from typing import Dict, List, Optional, Any
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('kibana_setup.log')
    ]
)
logger = logging.getLogger(__name__)

class KibanaDashboardSetup:
    """Handle Kibana dashboard setup and configuration"""
    
    def __init__(self, kibana_url: str = "http://localhost:5601", 
                 elasticsearch_url: str = "http://elasticsearch:9200",
                 username: str = "elastic", 
                 password: str = "changeme"):
        """Initialize with Kibana connection details"""
        self.kibana_url = kibana_url.rstrip('/')
        self.elasticsearch_url = elasticsearch_url.rstrip('/')
        self.auth = (username, password)
        self.headers = {
            'kbn-xsrf': 'true',
            'Content-Type': 'application/json'
        }
        self.space_id = "default"  # Use default space
    
    def _make_kibana_request(self, method: str, path: str, data: dict = None) -> Optional[dict]:
        """Make an authenticated request to the Kibana API"""
        url = f"{self.kibana_url}/s/{self.space_id}{path}"
        
        try:
            if method.upper() == 'GET':
                response = requests.get(
                    url, 
                    auth=self.auth, 
                    headers=self.headers,
                    verify=False
                )
            elif method.upper() == 'POST':
                response = requests.post(
                    url, 
                    auth=self.auth, 
                    headers=self.headers,
                    json=data,
                    verify=False
                )
            elif method.upper() == 'PUT':
                response = requests.put(
                    url, 
                    auth=self.auth, 
                    headers=self.headers,
                    json=data,
                    verify=False
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json() if response.text else {}
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Error making {method} request to {url}: {str(e)}"
            if hasattr(e, 'response') and e.response is not None:
                error_msg += f" - {e.response.text}"
            logger.error(error_msg)
            return None
    
    def create_index_pattern(self, pattern: str = "honeypot-*", time_field: str = "@timestamp") -> Optional[str]:
        """Create an index pattern in Kibana"""
        logger.info(f"Creating index pattern for {pattern}")
        
        # Check if index pattern already exists
        response = self._make_kibana_request(
            'GET', 
            f"/api/saved_objects/_find?type=index-pattern&search=title:'{pattern}'"
        )
        
        if response and response.get('saved_objects'):
            index_pattern_id = response['saved_objects'][0]['id']
            logger.info(f"Index pattern already exists with ID: {index_pattern_id}")
            return index_pattern_id
        
        # Create new index pattern
        data = {
            "attributes": {
                "title": pattern,
                "timeFieldName": time_field
            }
        }
        
        response = self._make_kibana_request(
            'POST', 
            "/api/saved_objects/index-pattern/honeypot",
            data=data
        )
        
        if response and 'id' in response:
            index_pattern_id = response['id']
            logger.info(f"Created index pattern with ID: {index_pattern_id}")
            return index_pattern_id
        else:
            logger.error("Failed to create index pattern")
            return None
    
    def import_objects(self, file_path: str) -> bool:
        """Import saved objects from a file"""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False
        
        try:
            with open(file_path, 'r') as f:
                objects = json.load(f)
            
            # Prepare the request body
            data = {
                "objects": objects,
                "overwrite": True
            }
            
            response = self._make_kibana_request(
                'POST',
                "/api/saved_objects/_import?overwrite=true",
                data=data
            )
            
            if response and not response.get('errors'):
                logger.info("Successfully imported objects")
                return True
            else:
                logger.error(f"Failed to import objects: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Error importing objects: {str(e)}")
            return False
    
    def setup_honeypot_dashboard(self) -> bool:
        """Set up the honeypot dashboard with all required visualizations"""
        # First, create the index pattern
        index_pattern_id = self.create_index_pattern()
        if not index_pattern_id:
            logger.error("Failed to create index pattern. Cannot proceed with dashboard setup.")
            return False
        
        # Wait for index pattern to be ready
        time.sleep(2)
        
        # Define the dashboard and visualizations
        dashboard = {
            "type": "dashboard",
            "id": "honeypot-dashboard",
            "attributes": {
                "title": "Honeypot Security Dashboard",
                "description": "Overview of honeypot activity and threats",
                "hits": 0,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    })
                },
                "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
                "panelsJSON": json.dumps([
                    # Top row - Overview
                    {
                        "gridData": {"x": 0, "y": 0, "w": 24, "h": 3, "i": "1"},
                        "panelIndex": "1",
                        "version": "7.15.0",
                        "type": "visualization",
                        "embeddableConfig": {},
                        "panelRefName": "panel_1"
                    },
                    # Second row - Threat Level and Activity
                    {
                        "gridData": {"x": 0, "y": 3, "w": 12, "h": 6, "i": "2"},
                        "panelIndex": "2",
                        "version": "7.15.0",
                        "type": "visualization",
                        "embeddableConfig": {},
                        "panelRefName": "panel_2"
                    },
                    {
                        "gridData": {"x": 12, "y": 3, "w": 12, "h": 6, "i": "3"},
                        "panelIndex": "3",
                        "version": "7.15.0",
                        "type": "visualization",
                        "embeddableConfig": {},
                        "panelRefName": "panel_3"
                    },
                    # Third row - Commands and Geo Map
                    {
                        "gridData": {"x": 0, "y": 9, "w": 12, "h": 6, "i": "4"},
                        "panelIndex": "4",
                        "version": "7.15.0",
                        "type": "visualization",
                        "embeddableConfig": {},
                        "panelRefName": "panel_4"
                    },
                    {
                        "gridData": {"x": 12, "y": 9, "w": 12, "h": 6, "i": "5"},
                        "panelIndex": "5",
                        "version": "7.15.0",
                        "type": "map",
                        "embeddableConfig": {},
                        "panelRefName": "panel_5"
                    },
                    # Fourth row - Timeline
                    {
                        "gridData": {"x": 0, "y": 15, "w": 24, "h": 6, "i": "6"},
                        "panelIndex": "6",
                        "version": "7.15.0",
                        "type": "visualization",
                        "embeddableConfig": {},
                        "panelRefName": "panel_6"
                    }
                ])
            },
            "references": [
                {
                    "type": "index-pattern",
                    "id": index_pattern_id,
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index"
                }
            ]
        }
        
        # Save the dashboard
        response = self._make_kibana_request(
            'POST',
            "/api/saved_objects/dashboard/honeypot-dashboard",
            data=dashboard
        )
        
        if response and 'id' in response:
            logger.info("Successfully created Honeypot Security Dashboard")
            return True
        else:
            logger.error("Failed to create dashboard")
            return False

def main():
    """Main function to set up Kibana dashboard"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Set up Kibana dashboard for ML-Powered Honeypot')
    parser.add_argument('--kibana-url', type=str, default='http://localhost:5601',
                      help='Kibana URL (default: http://localhost:5601)')
    parser.add_argument('--elasticsearch-url', type=str, default='http://elasticsearch:9200',
                      help='Elasticsearch URL (default: http://elasticsearch:9200)')
    parser.add_argument('--username', type=str, default='elastic',
                      help='Elasticsearch username (default: elastic)')
    parser.add_argument('--password', type=str, default='changeme',
                      help='Elasticsearch password (default: changeme)')
    
    args = parser.parse_args()
    
    # Initialize the setup
    setup = KibanaDashboardSetup(
        kibana_url=args.kibana_url,
        elasticsearch_url=args.elasticsearch_url,
        username=args.username,
        password=args.password
    )
    
    # Create the dashboard
    success = setup.setup_honeypot_dashboard()
    
    if success:
        print("\n✅ Kibana dashboard setup completed successfully!")
        print(f"\nAccess your dashboard at: {args.kibana_url}/app/dashboards#/view/honeypot-dashboard")
        print("\nNext steps:")
        print("1. Generate sample data: python scripts/generate_sample_logs.py --send-to-logstash")
        print("2. Explore the dashboard and customize as needed")
    else:
        print("\n❌ Failed to set up Kibana dashboard. Check the logs for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()
