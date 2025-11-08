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

    GOOGLE = "google"
    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"


class ProviderConfig(BaseModel):
    """Configuration for a specific AI provider."""

    api_key: Optional[str] = None
    model: Optional[str] = None
    endpoint: Optional[str] = None
    timeout: int = 60
    max_retries: int = 3


class AIConfig(BaseModel):
    """AI integration configuration."""

    default_provider: AIProvider = Field(default=AIProvider.GOOGLE)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    enable_caching: bool = True
    cache_ttl: int = 3600  # seconds

    @classmethod
    def load_from_file(cls, config_path: Optional[Path] = None) -> "AIConfig":
        """Load configuration from YAML file."""
        if config_path is None:
            config_path = Path.home() / ".audit-agent" / "config.yaml"

        if not config_path.exists():
            logger.info(
                "Config file not found at %s, using defaults and environment variables", config_path
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
        providers = {}

        # Google AI Studio (Gemini)
        google_api_key = os.getenv("GOOGLE_AI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if google_api_key:
            providers["google"] = ProviderConfig(
                api_key=google_api_key,
                model=os.getenv("GOOGLE_AI_MODEL", "gemini-2.0-flash-exp"),
            )

        # OpenAI
        openai_api_key = os.getenv("OPENAI_API_KEY")
        if openai_api_key:
            providers["openai"] = ProviderConfig(
                api_key=openai_api_key,
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            )

        # Azure OpenAI
        azure_api_key = os.getenv("AZURE_OPENAI_API_KEY")
        if azure_api_key:
            providers["azure_openai"] = ProviderConfig(
                api_key=azure_api_key,
                model=os.getenv("AZURE_OPENAI_MODEL"),
                endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
            )

        # Determine default provider
        default_provider = AIProvider.GOOGLE
        if os.getenv("AI_PROVIDER"):
            try:
                default_provider = AIProvider(os.getenv("AI_PROVIDER").lower())
            except ValueError:
                logger.warning(
                    "Invalid AI_PROVIDER: %s, using Google", os.getenv('AI_PROVIDER')
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

        if not config.api_key:
            msg = f"No API key configured for provider: {provider.value}"
            raise ValueError(msg)

        return config

    def save_to_file(self, config_path: Optional[Path] = None) -> None:
        """Save configuration to YAML file."""
        if config_path is None:
            config_path = Path.home() / ".audit-agent" / "config.yaml"

        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Load existing config if present
        existing_data = {}
        if config_path.exists():
            with open(config_path) as f:
                existing_data = yaml.safe_load(f) or {}

        # Update AI section
        existing_data["ai"] = self.model_dump(exclude_none=True)

        with open(config_path, "w") as f:
            yaml.dump(existing_data, f, default_flow_style=False, sort_keys=False)

        logger.info("Configuration saved to %s", config_path)
