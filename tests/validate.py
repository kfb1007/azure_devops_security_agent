"""
Validation script for the Azure DevOps Security Alert Agent.

This script validates the agent's functionality by:
1. Testing authentication
2. Testing API connectivity
3. Testing data collection
4. Testing data storage
5. Validating metadata extraction
"""

import os
import sys
import logging
import json
from pathlib import Path

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.auth.oauth import PersonalAccessTokenAuth
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


def validate_authentication():
    """Test authentication with a mock PAT."""
    logger.info("Validating authentication...")
    
    # Create a mock PAT auth provider
    auth = PersonalAccessTokenAuth("mock_pat")
    headers = auth.get_auth_header()
    
    # Validate the headers
    if "Authorization" in headers and headers["Authorization"].startswith("Basic "):
        logger.info("✓ Authentication header generation successful")
        return True
    else:
        logger.error("✗ Authentication header generation failed")
        return False


def validate_api_client():
    """Test API client initialization."""
    logger.info("Validating API client...")
    
    # Create a mock auth provider
    auth = PersonalAccessTokenAuth("mock_pat")
    
    # Create API client
    client = AzureDevOpsClient(
        organization="test-org",
        project="test-project",
        auth_provider=auth
    )
    
    # Validate client properties
    if (client.organization == "test-org" and 
        client.project == "test-project" and
        client.base_url == "https://advsec.dev.azure.com/test-org/test-project/_apis"):
        logger.info("✓ API client initialization successful")
        return True
    else:
        logger.error("✗ API client initialization failed")
        return False


def validate_data_models():
    """Test data model parsing from API response."""
    logger.info("Validating data models...")
    
    # Sample API response
    sample_data = {
        "alertId": 12345,
        "alertType": "code",
        "confidence": "high",
        "severity": "critical",
        "state": "active",
        "firstSeenDate": "2025-05-01T10:00:00Z",
        "lastSeenDate": "2025-06-01T10:00:00Z",
        "gitRef": "refs/heads/main",
        "physicalLocations": [
            {
                "filePath": "src/main.py",
                "startLine": 10,
                "endLine": 15
            }
        ],
        "logicalLocations": [
            {
                "name": "main_function",
                "kind": "function"
            }
        ],
        "rule": {
            "id": "rule-123",
            "name": "Insecure Function",
            "description": "This function has security issues"
        }
    }
    
    try:
        # Parse the sample data
        alert = Alert.from_api(sample_data)
        
        # Validate parsed data
        if (alert.alert_id == 12345 and
            alert.alert_type.value == "code" and
            alert.confidence.value == "high" and
            alert.severity.value == "critical" and
            alert.state.value == "active" and
            alert.git_ref == "refs/heads/main" and
            len(alert.physical_locations) == 1 and
            alert.physical_locations[0].file_path == "src/main.py" and
            len(alert.logical_locations) == 1 and
            alert.logical_locations[0].name == "main_function" and
            alert.rule.id == "rule-123"):
            logger.info("✓ Data model parsing successful")
            return True, alert
        else:
            logger.error("✗ Data model parsing failed - incorrect values")
            return False, None
    except Exception as e:
        logger.error(f"✗ Data model parsing failed with error: {e}")
        return False, None


def validate_database():
    """Test database operations."""
    logger.info("Validating database operations...")
    
    # Create a temporary database
    db_path = "test_alerts.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    try:
        # Initialize database
        db = AlertDatabase(db_path)
        
        # Get a sample alert
        success, alert = validate_data_models()
        if not success:
            return False
        
        # Store the alert
        alert_id = db.store_alert(
            alert=alert,
            organization="test-org",
            project="test-project",
            repository="test-repo"
        )
        
        if alert_id <= 0:
            logger.error("✗ Alert storage failed")
            return False
        
        # Retrieve the alert
        alerts = db.get_alerts(
            organization="test-org",
            project="test-project",
            repository="test-repo"
        )
        
        if len(alerts) != 1 or alerts[0]["alert_id"] != 12345:
            logger.error("✗ Alert retrieval failed")
            return False
        
        logger.info("✓ Database operations successful")
        return True
    except Exception as e:
        logger.error(f"✗ Database operations failed with error: {e}")
        return False
    finally:
        # Clean up
        if os.path.exists(db_path):
            os.remove(db_path)


def validate_metadata_extraction():
    """Test metadata extraction from alerts."""
    logger.info("Validating metadata extraction...")
    
    # Get a sample alert
    success, alert = validate_data_models()
    if not success:
        return False
    
    # Validate metadata extraction
    try:
        # Check core metadata
        if (alert.severity.value == "critical" and
            alert.alert_type.value == "code" and
            alert.state.value == "active" and
            alert.confidence.value == "high"):
            
            # Check location metadata
            if (len(alert.physical_locations) > 0 and
                alert.physical_locations[0].file_path == "src/main.py" and
                alert.physical_locations[0].start_line == 10 and
                alert.physical_locations[0].end_line == 15):
                
                # Check rule metadata
                if (alert.rule.id == "rule-123" and
                    alert.rule.name == "Insecure Function"):
                    
                    logger.info("✓ Metadata extraction successful")
                    return True
        
        logger.error("✗ Metadata extraction failed - incorrect values")
        return False
    except Exception as e:
        logger.error(f"✗ Metadata extraction failed with error: {e}")
        return False


def run_validation():
    """Run all validation tests."""
    logger.info("Starting validation of Azure DevOps Security Alert Agent")
    
    # Track validation results
    results = {
        "authentication": validate_authentication(),
        "api_client": validate_api_client(),
        "data_models": validate_data_models()[0],
        "database": validate_database(),
        "metadata_extraction": validate_metadata_extraction()
    }
    
    # Report results
    logger.info("\n=== Validation Results ===")
    all_passed = True
    for test, passed in results.items():
        status = "PASSED" if passed else "FAILED"
        logger.info(f"{test.ljust(20)}: {status}")
        if not passed:
            all_passed = False
    
    if all_passed:
        logger.info("\n✓ All validation tests passed!")
        return True
    else:
        logger.error("\n✗ Some validation tests failed")
        return False


if __name__ == "__main__":
    success = run_validation()
    sys.exit(0 if success else 1)
