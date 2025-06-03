"""
API client for Azure DevOps Advanced Security alerts.
"""

import requests
import logging
from typing import Dict, List, Optional, Any
from urllib.parse import quote

logger = logging.getLogger(__name__)


class AzureDevOpsClient:
    """
    Client for interacting with Azure DevOps Advanced Security APIs.
    """
    
    def __init__(self, organization: str, project: str, auth_provider: Any):
        """
        Initialize the Azure DevOps API client.
        
        Args:
            organization: Azure DevOps organization name
            project: Azure DevOps project name
            auth_provider: Authentication provider that implements get_auth_header()
        """
        self.organization = organization
        self.project = project
        self.auth_provider = auth_provider
        self.base_url = f"https://advsec.dev.azure.com/{quote(organization)}/{quote(project)}/_apis"
        self.api_version = "7.2-preview.1"
    
    def get_alerts(self, repository: str, **kwargs) -> Dict:
        """
        Get alerts for a repository.
        
        Args:
            repository: Repository name or ID
            **kwargs: Optional filter parameters
            
        Returns:
            Dict: Response containing alerts
        """
        url = f"{self.base_url}/alert/repositories/{quote(repository)}/alerts"
        params = {"api-version": self.api_version}
        
        # Add optional filter parameters
        for key, value in kwargs.items():
            if key.startswith("criteria."):
                params[key] = value
        
        headers = self.auth_provider.get_auth_header()
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching alerts: {e}")
            return {"error": str(e)}
    
    def get_alert(self, repository: str, alert_id: int) -> Dict:
        """
        Get a specific alert by ID.
        
        Args:
            repository: Repository name or ID
            alert_id: ID of the alert to retrieve
            
        Returns:
            Dict: Alert details
        """
        url = f"{self.base_url}/alert/repositories/{quote(repository)}/alerts/{alert_id}"
        params = {"api-version": self.api_version}
        headers = self.auth_provider.get_auth_header()
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching alert {alert_id}: {e}")
            return {"error": str(e)}
    
    def get_repositories(self) -> List[Dict]:
        """
        Get repositories in the project.
        
        Returns:
            List[Dict]: List of repositories
        """
        url = f"https://dev.azure.com/{quote(self.organization)}/{quote(self.project)}/_apis/git/repositories"
        params = {"api-version": "7.2-preview.1"}
        headers = self.auth_provider.get_auth_header()
        
        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json().get("value", [])
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching repositories: {e}")
            return []
