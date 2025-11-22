"""
Token management for AuditAgent CLI.
Handles secure storage and retrieval of authentication tokens.
"""

import json
import os
from pathlib import Path
from typing import Optional


class TokenManager:
    """Manages authentication tokens for the CLI."""

    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize TokenManager.
        
        Args:
            config_dir: Directory to store config. Defaults to ~/.auditagent
        """
        if config_dir is None:
            config_dir = Path.home() / ".auditagent"
        
        self.config_dir = config_dir
        self.config_file = self.config_dir / "config.json"
        
        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    
    def save_token(self, token: str, api_url: str = "http://localhost:8000") -> None:
        """
        Save authentication token to config file.
        
        Args:
            token: The authentication token
            api_url: The API base URL
        """
        config = self._load_config()
        config["token"] = token
        config["api_url"] = api_url
        
        # Write with restricted permissions
        with open(self.config_file, "w") as f:
            json.dump(config, f, indent=2)
        
        # Ensure file has restricted permissions
        os.chmod(self.config_file, 0o600)
    
    def get_token(self) -> Optional[str]:
        """
        Retrieve the stored authentication token.
        
        Returns:
            The token if found, None otherwise
        """
        config = self._load_config()
        return config.get("token")
    
    def get_api_url(self) -> str:
        """
        Get the configured API URL.
        
        Returns:
            The API URL (defaults to localhost:8000)
        """
        config = self._load_config()
        return config.get("api_url", "http://localhost:8000")
    
    def clear_token(self) -> None:
        """Clear the stored authentication token."""
        config = self._load_config()
        config.pop("token", None)
        
        with open(self.config_file, "w") as f:
            json.dump(config, f, indent=2)
    
    def _load_config(self) -> dict:
        """Load configuration from file."""
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
