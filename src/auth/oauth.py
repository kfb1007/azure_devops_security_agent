"""
Authentication module for Azure DevOps API access.
"""

import os
import requests
from typing import Dict, Optional


class OAuthAuthentication:
    """
    OAuth 2.0 authentication for Azure DevOps API.
    
    This class handles the OAuth 2.0 authentication flow for Azure DevOps,
    including token acquisition and refresh.
    """
    
    def __init__(self, client_id: str, client_secret: str, tenant_id: str):
        """
        Initialize OAuth authentication with client credentials.
        
        Args:
            client_id: The client ID for the Azure AD application
            client_secret: The client secret for the Azure AD application
            tenant_id: The tenant ID for the Azure AD directory
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.token = None
        self.token_expiry = None
    
    def get_token(self) -> str:
        """
        Get a valid access token, refreshing if necessary.
        
        Returns:
            str: The access token for API calls
        """
        # Check if token exists and is still valid
        if self._is_token_valid():
            return self.token
        
        # Otherwise, acquire a new token
        return self._acquire_token()
    
    def _is_token_valid(self) -> bool:
        """
        Check if the current token is valid and not expired.
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        # Implementation would check token expiry
        # For now, always return False to force token acquisition
        return False
    
    def _acquire_token(self) -> str:
        """
        Acquire a new access token from Azure AD.
        
        Returns:
            str: The new access token
        """
        # In a real implementation, this would make an OAuth token request
        # For now, return a placeholder
        self.token = "placeholder_oauth_token"
        return self.token
    
    def get_auth_header(self) -> Dict[str, str]:
        """
        Get the authorization header for API requests.
        
        Returns:
            Dict[str, str]: The authorization header
        """
        token = self.get_token()
        return {"Authorization": f"Bearer {token}"}


class PersonalAccessTokenAuth:
    """
    Personal Access Token (PAT) authentication for Azure DevOps API.
    """
    
    def __init__(self, pat: str):
        """
        Initialize PAT authentication.
        
        Args:
            pat: The Personal Access Token for Azure DevOps
        """
        self.pat = pat
    
    def get_auth_header(self) -> Dict[str, str]:
        """
        Get the authorization header for API requests.
        
        Returns:
            Dict[str, str]: The authorization header
        """
        import base64
        encoded_pat = base64.b64encode(f":{self.pat}".encode()).decode()
        return {"Authorization": f"Basic {encoded_pat}"}


def create_auth_from_config(config: Dict) -> Optional[object]:
    """
    Create an authentication object from configuration.
    
    Args:
        config: Configuration dictionary with authentication settings
        
    Returns:
        Authentication object (OAuthAuthentication or PersonalAccessTokenAuth)
    """
    auth_type = config.get("auth_type", "").lower()
    
    if auth_type == "oauth":
        return OAuthAuthentication(
            client_id=config.get("client_id", ""),
            client_secret=config.get("client_secret", ""),
            tenant_id=config.get("tenant_id", "")
        )
    elif auth_type == "pat":
        return PersonalAccessTokenAuth(pat=config.get("pat", ""))
    else:
        return None
