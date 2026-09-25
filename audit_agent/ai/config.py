"""
Configuration management for AI integration.
"""

import os
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from ..core.logging_config import get_logger

logger = get_logger(__name__)


class AIProvider(str, Enum):
    """Supported AI providers."""

    OPENCODE = "opencode"


class ProviderConfig(BaseModel):
    """Configuration for a specific AI provider."""

    api_key: Optional[str] = None
    model: Optional[str] = None
    endpoint: Optional[str] = None
    timeout: int = 60
    max_retries: int = 3


class AIConfig(BaseModel):
    """AI integration configuration."""

    default_provider: AIProvider = Field(default=AIProvider.OPENCODE)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)

    @classmethod
    def load_from_file(cls, config_path: Optional[Path] = None) -> "AIConfig":
        """Load configuration from YAML file."""
        if config_path is None:
            config_path = Path.home() / ".audit-agent" / "config.yaml"

        if not config_path.exists():
            logger.info(
                "Config file not found at %s, using defaults and environment variables",
                config_path,
            )
            return cls.load_from_env()

        try:
            with open(config_path) as f:
                data = yaml.safe_load(f) or {}
                ai_config = data.get("ai", {})
                return cls(**ai_config)
        except Exception as e:
            logger.warning("Failed to load config from %s: %s", config_path, e)
            return cls.load_from_env()

    @classmethod
    def load_from_env(cls) -> "AIConfig":
        """Load configuration from environment variables."""
        # OpenCode owns provider credentials and model routing, so no API key
        # is required here. OPENCODE_MODEL selects which OpenCode model to use.
        providers = {
            "opencode": ProviderConfig(
                model=os.getenv("OPENCODE_MODEL")
                or "opencode-go/deepseek-v4.1-flash",
                timeout=int(os.getenv("OPENCODE_TIMEOUT", "60")),
            )
        }

        # Determine default provider
        default_provider = AIProvider.OPENCODE
        if os.getenv("AI_PROVIDER"):
            try:
                default_provider = AIProvider(os.getenv("AI_PROVIDER").lower())
            except ValueError:
                logger.warning(
                    "Invalid AI_PROVIDER: %s, using OpenCode", os.getenv("AI_PROVIDER")
                )

        return cls(default_provider=default_provider, providers=providers)

    def get_provider_config(
        self, provider: Optional[AIProvider] = None
    ) -> ProviderConfig:
        """Get configuration for a specific provider."""
        provider = provider or self.default_provider
        config = self.providers.get(provider.value)

        if not config:
            msg = f"No configuration found for provider: {provider.value}"
            raise ValueError(msg)

        return config
