"""
Main entry point for the Azure DevOps Security Alert Agent.
"""

import argparse
import logging
import os
import sys
import yaml
from pathlib import Path

from src.auth.oauth import create_auth_from_config
from src.api.client import AzureDevOpsClient
from src.api.models import Alert
from src.storage.database import AlertDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)


def load_config(config_path):
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        sys.exit(1)


def collect_alerts(config):
    """Collect alerts from Azure DevOps."""
    # Create authentication provider
    auth_provider = create_auth_from_config(config.get('auth', {}))
    if not auth_provider:
        logger.error("Failed to create authentication provider")
        return False
    
    # Create API client
    client = AzureDevOpsClient(
        organization=config.get('organization', ''),
        project=config.get('project', ''),
        auth_provider=auth_provider
    )
    
    # Create database
    db_path = config.get('database', {}).get('path', 'data/alerts.db')
    db = AlertDatabase(db_path)
    
    # Get repositories
    repositories = config.get('repositories', [])
    if not repositories:
        logger.info("No repositories specified, fetching all repositories")
        try:
            repo_list = client.get_repositories()
            repositories = [repo.get('name') for repo in repo_list]
        except Exception as e:
            logger.error(f"Error fetching repositories: {e}")
            return False
    
    # Collect alerts for each repository
    total_alerts = 0
    for repo in repositories:
        logger.info(f"Collecting alerts for repository: {repo}")
        try:
            # Get alerts
            response = client.get_alerts(repo)
            if 'error' in response:
                logger.error(f"Error fetching alerts for {repo}: {response['error']}")
                continue
            
            alerts = response.get('value', [])
            logger.info(f"Found {len(alerts)} alerts in repository {repo}")
            
            # Store alerts
            for alert_data in alerts:
                try:
                    alert = Alert.from_api(alert_data)
                    db.store_alert(
                        alert=alert,
                        organization=config.get('organization', ''),
                        project=config.get('project', ''),
                        repository=repo
                    )
                    total_alerts += 1
                except Exception as e:
                    logger.error(f"Error processing alert: {e}")
        except Exception as e:
            logger.error(f"Error collecting alerts for repository {repo}: {e}")
    
    logger.info(f"Total alerts collected: {total_alerts}")
    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Azure DevOps Security Alert Agent')
    parser.add_argument('--config', default='config/config.yaml', help='Path to configuration file')
    args = parser.parse_args()
    
    logger.info("Starting Azure DevOps Security Alert Agent")
    
    # Load configuration
    config = load_config(args.config)
    
    # Collect alerts
    success = collect_alerts(config)
    
    if success:
        logger.info("Alert collection completed successfully")
    else:
        logger.error("Alert collection failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
