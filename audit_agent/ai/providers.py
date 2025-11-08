"""
AI provider implementations for different services.
"""

import json
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

import requests

from ..core.logging_config import get_logger
from .config import AIConfig, AIProvider, ProviderConfig

logger = get_logger(__name__)


class AIProviderBase(ABC):
    """Base class for AI providers."""

    def __init__(self, config: ProviderConfig):
        self.config = config
        self.api_key = config.api_key
        self.model = config.model
        self.timeout = config.timeout
        self.max_retries = config.max_retries

    @abstractmethod
    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Generate text from a prompt."""
        pass

    @abstractmethod
    def generate_structured_output(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
    ) -> dict[str, Any]:
        """Generate structured JSON output from a prompt."""
        pass


class GoogleAIProvider(AIProviderBase):
    """Google AI Studio (Gemini) provider implementation."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self.model = config.model or "gemini-1.5-flash"  # Use stable flash model

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Generate text using Gemini API."""
        url = f"{self.base_url}/models/{self.model}:generateContent"

        # Build the contents array
        contents = []
        if system_prompt:
            contents.append({"role": "user", "parts": [{"text": system_prompt}]})
            contents.append(
                {
                    "role": "model",
                    "parts": [
                        {"text": "Understood. I will follow these instructions."}
                    ],
                }
            )

        contents.append({"role": "user", "parts": [{"text": prompt}]})

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens or 8192,
            },
        }

        headers = {
            "Content-Type": "application/json",
            "X-goog-api-key": self.api_key,
        }

        logger.debug(f"Calling Google AI with model {self.model}")

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                )
                response.raise_for_status()

                result = response.json()
                if "candidates" in result and result["candidates"]:
                    text = result["candidates"][0]["content"]["parts"][0]["text"]
                    logger.debug(f"Generated {len(text)} characters")
                    return text
                else:
                    msg = f"No candidates in response: {result}"
                    raise ValueError(msg)

            except requests.exceptions.RequestException as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt == self.max_retries - 1:
                    raise
                # Exponential backoff for rate limits
                if "429" in str(e):
                    wait_time = (2 ** attempt) * 2  # 2, 4, 8 seconds
                    logger.info(f"Rate limited. Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    time.sleep(1)
            except (KeyError, IndexError, ValueError) as e:
                logger.error(f"Failed to parse response: {e}")
                raise

        msg = "Max retries exceeded"
        raise RuntimeError(msg)

    def generate_structured_output(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
    ) -> dict[str, Any]:
        """Generate structured JSON output using Gemini API."""
        # Enhance system prompt to request JSON
        json_system = (
            "You are a precise JSON generator. "
            "Always respond with valid JSON only, no markdown formatting, no explanations."
        )
        if system_prompt:
            json_system += f"\n\n{system_prompt}"

        json_prompt = f"{prompt}\n\nRespond with valid JSON only."

        response_text = self.generate_text(
            json_prompt, system_prompt=json_system, temperature=temperature
        )

        # Clean up response (remove markdown if present)
        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]

        response_text = response_text.strip()

        try:
            return json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Response text: {response_text}")
            raise


class OpenAIProvider(AIProviderBase):
    """OpenAI provider implementation (for future use)."""

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.base_url = config.endpoint or "https://api.openai.com/v1"
        self.model = config.model or "gpt-4o-mini"

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Generate text using OpenAI API."""
        url = f"{self.base_url}/chat/completions"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }

        if max_tokens:
            payload["max_tokens"] = max_tokens

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        logger.debug(f"Calling OpenAI with model {self.model}")

        for attempt in range(self.max_retries):
            try:
                response = requests.post(
                    url, json=payload, headers=headers, timeout=self.timeout
                )
                response.raise_for_status()

                result = response.json()
                text = result["choices"][0]["message"]["content"]
                logger.debug(f"Generated {len(text)} characters")
                return text

            except requests.exceptions.RequestException as e:
                logger.warning(f"Attempt {attempt + 1} failed: {e}")
                if attempt == self.max_retries - 1:
                    raise

        msg = "Max retries exceeded"
        raise RuntimeError(msg)

    def generate_structured_output(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
    ) -> dict[str, Any]:
        """Generate structured JSON output using OpenAI API."""
        json_system = (
            "You are a precise JSON generator. "
            "Always respond with valid JSON only, no markdown formatting."
        )
        if system_prompt:
            json_system += f"\n\n{system_prompt}"

        json_prompt = f"{prompt}\n\nRespond with valid JSON only."

        response_text = self.generate_text(
            json_prompt, system_prompt=json_system, temperature=temperature
        )

        response_text = response_text.strip()
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]

        response_text = response_text.strip()

        try:
            return json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            raise


def get_provider(
    config: AIConfig, provider: Optional[AIProvider] = None
) -> AIProviderBase:
    """Factory function to get an AI provider instance."""
    provider = provider or config.default_provider
    provider_config = config.get_provider_config(provider)

    if provider == AIProvider.GOOGLE:
        return GoogleAIProvider(provider_config)
    elif provider == AIProvider.OPENAI:
        return OpenAIProvider(provider_config)
    elif provider == AIProvider.AZURE_OPENAI:
        # Azure uses same implementation as OpenAI but with custom endpoint
        return OpenAIProvider(provider_config)
    else:
        msg = f"Unsupported provider: {provider}"
        raise ValueError(msg)
