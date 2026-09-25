"""
AI provider implementations for different services.
"""

import json
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Any, Optional

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


class OpenCodeProvider(AIProviderBase):
    """
    OpenCode provider.

    Shells out to the local ``opencode run`` headless mode and parses the
    JSON event stream it emits. No API key or network client is needed here:
    OpenCode owns provider credentials and model routing, so any model
    configured in OpenCode (e.g. ``opencode-go/deepseek-v4.1-flash``) becomes
    usable as an AuditAgent AI backend.
    """

    # ponytail: default model is the one we actually route in this environment.
    # Swap via OPENCODE_MODEL / ProviderConfig.model for any other OpenCode model.
    DEFAULT_MODEL = "opencode-go/deepseek-v4.1-flash"

    def __init__(self, config: ProviderConfig):
        super().__init__(config)
        self.model = config.model or self.DEFAULT_MODEL
        self.binary = os.getenv("OPENCODE_BIN", "opencode")

    def _run(self, message: str) -> str:
        """Invoke ``opencode run`` once and return the assistant's text."""
        binary = shutil.which(self.binary) or self.binary
        cmd = [
            binary,
            "run",
            "--model",
            self.model,
            "--format",
            "json",
            message,
        ]
        logger.debug("Calling OpenCode with model %s", self.model)

        try:
            proc = subprocess.run(  # noqa: S603 - fixed binary + arg list, no shell
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            msg = f"OpenCode call timed out after {self.timeout}s"
            raise RuntimeError(msg) from e
        except FileNotFoundError as e:
            msg = (
                f"OpenCode binary {self.binary!r} not found. "
                "Install OpenCode or set OPENCODE_BIN."
            )
            raise RuntimeError(msg) from e

        if proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip() or "<no output>"
            msg = f"OpenCode exited {proc.returncode}: {detail}"
            raise RuntimeError(msg)

        return self._extract_text(proc.stdout)

    @staticmethod
    def _extract_text(stdout: str) -> str:
        """Concatenate ``text`` events from the OpenCode JSON event stream."""
        parts = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                logger.debug("Skipping non-JSON OpenCode output: %s", line)
                continue
            if event.get("type") == "text":
                text = event.get("part", {}).get("text")
                if text:
                    parts.append(text)
        return "".join(parts)

    def generate_text(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Generate text using a headless OpenCode run."""
        # ponytail: ``opencode run`` has no system-prompt flag, so fold the
        # system prompt into the message. Fine for single-turn completions.
        message = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

        last_error = None
        for attempt in range(self.max_retries):
            try:
                text = self._run(message)
                if not text:
                    msg = "OpenCode returned no text events"
                    raise ValueError(msg)
                logger.debug("Generated %s characters", len(text))
                return text
            except (RuntimeError, ValueError) as e:
                last_error = e
                logger.warning("Attempt %s failed: %s", attempt + 1, e)

        msg = f"OpenCode call failed after {self.max_retries} attempts: {last_error}"
        raise RuntimeError(msg)

    def generate_structured_output(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.3,
    ) -> dict[str, Any]:
        """Generate structured JSON output using a headless OpenCode run."""
        json_system = (
            "You are a precise JSON generator. "
            "Always respond with valid JSON only, no markdown formatting, no explanations."
        )
        if system_prompt:
            json_system += f"\n\n{system_prompt}"

        json_prompt = f"{prompt}\n\nRespond with valid JSON only."

        response_text = _strip_code_fence(
            self.generate_text(
                json_prompt, system_prompt=json_system, temperature=temperature
            )
        )

        try:
            return json.loads(response_text)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse JSON response: %s", e)
            logger.debug("Response text: %s", response_text)
            raise


def _strip_code_fence(text: str) -> str:
    """Remove a surrounding markdown code fence, if present."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def get_provider(
    config: AIConfig, provider: Optional[AIProvider] = None
) -> AIProviderBase:
    """Factory function to get an AI provider instance."""
    provider = provider or config.default_provider
    provider_config = config.get_provider_config(provider)

    if provider == AIProvider.OPENCODE:
        return OpenCodeProvider(provider_config)

    msg = f"Unsupported provider: {provider}"
    raise ValueError(msg)
