"""
Example usage script for the Azure DevOps Security Alert Agent analysis capabilities.
"""

import argparse
import logging
import sys
import yaml
import json
from pathlib import Path
from datetime import datetime

from src.analysis.query import AlertAnalyzer

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


def analyze_alerts(config):
    """Analyze alerts from the database."""
    # Create analyzer
    db_path = config.get('database', {}).get('path', 'data/alerts.db')
    analyzer = AlertAnalyzer(db_path)
    
    # Get organization and project from config
    organization = config.get('organization', '')
    project = config.get('project', '')
    
    if not organization or not project:
        logger.error("Organization and project must be specified in the configuration")
        return False
    
    # Get repository from config or command line
    repositories = config.get('repositories', [])
    repository = repositories[0] if repositories else None
    
    # Generate analysis reports
    reports = {}
    
    # Alert counts by severity
    try:
        reports['severity_counts'] = analyzer.get_alert_counts_by_severity(
            organization=organization,
            project=project,
            repository=repository
        )
        logger.info(f"Alert counts by severity: {reports['severity_counts']}")
    except Exception as e:
        logger.error(f"Error getting alert counts by severity: {e}")
    
    # Alert counts by state
    try:
        reports['state_counts'] = analyzer.get_alert_counts_by_state(
            organization=organization,
            project=project,
            repository=repository
        )
        logger.info(f"Alert counts by state: {reports['state_counts']}")
    except Exception as e:
        logger.error(f"Error getting alert counts by state: {e}")
    
    # Alert counts by type
    try:
        reports['type_counts'] = analyzer.get_alert_counts_by_type(
            organization=organization,
            project=project,
            repository=repository
        )
        logger.info(f"Alert counts by type: {reports['type_counts']}")
    except Exception as e:
        logger.error(f"Error getting alert counts by type: {e}")
    
    # Alert trend
    try:
        reports['alert_trend'] = analyzer.get_alert_trend(
            organization=organization,
            project=project,
            repository=repository,
            days=30,
            interval='day'
        )
        logger.info(f"Alert trend: {reports['alert_trend']}")
    except Exception as e:
        logger.error(f"Error getting alert trend: {e}")
    
    # Top repositories by alerts
    try:
        reports['top_repositories'] = analyzer.get_top_repositories_by_alerts(
            organization=organization,
            project=project,
            limit=10
        )
        logger.info(f"Top repositories by alerts: {reports['top_repositories']}")
    except Exception as e:
        logger.error(f"Error getting top repositories: {e}")
    
    # Top rules
    try:
        reports['top_rules'] = analyzer.get_top_rules(
            organization=organization,
            project=project,
            repository=repository,
            limit=10
        )
        logger.info(f"Top rules: {reports['top_rules']}")
    except Exception as e:
        logger.error(f"Error getting top rules: {e}")
    
    # Alerts by file path
    try:
        reports['alerts_by_file'] = analyzer.get_alerts_by_file_path(
            organization=organization,
            project=project,
            repository=repository,
            limit=10
        )
        logger.info(f"Alerts by file path: {reports['alerts_by_file']}")
    except Exception as e:
        logger.error(f"Error getting alerts by file path: {e}")
    
    # Save reports to file
    try:
        reports_dir = Path('reports')
        reports_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = reports_dir / f"analysis_report_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            json.dump(reports, f, indent=2)
        
        logger.info(f"Analysis report saved to {report_file}")
    except Exception as e:
        logger.error(f"Error saving analysis report: {e}")
    
    return True


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Azure DevOps Security Alert Analyzer')
    parser.add_argument('--config', default='config/config.yaml', help='Path to configuration file')
    args = parser.parse_args()
    
    logger.info("Starting Azure DevOps Security Alert Analyzer")
    
    # Load configuration
    config = load_config(args.config)
    
    # Analyze alerts
    success = analyze_alerts(config)
    
    if success:
        logger.info("Alert analysis completed successfully")
    else:
        logger.error("Alert analysis failed")
        sys.exit(1)


if __name__ == '__main__':
    main()
