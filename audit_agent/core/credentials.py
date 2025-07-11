"""
Credential management system for AuditAgent.
Handles secure credential prompting and authentication.
"""

import getpass
import os
import sys
from typing import Any, Dict, Optional

import paramiko

from ..core.logging_config import get_logger

logger = get_logger(__name__)


class CredentialManager:
    """Manages secure credential prompting and storage."""

    def __init__(self):
        self._credential_cache: Dict[str, Any] = {}
        self._ssh_agent_available = self._check_ssh_agent()

    def _check_ssh_agent(self) -> bool:
        """Check if SSH agent is available."""
        try:
            # Check if SSH_AUTH_SOCK environment variable is set
            if not os.environ.get("SSH_AUTH_SOCK"):
                logger.debug("SSH_AUTH_SOCK not set")
                return False

            agent = paramiko.Agent()
            keys = agent.get_keys()
            logger.debug(f"SSH agent has {len(keys)} keys available")
            return len(keys) > 0
        except Exception as e:
            logger.debug(f"SSH agent check failed: {e}")
            return False

    def get_ssh_password(self, username: str, host: str) -> Optional[str]:
        """
        Get SSH password for a user.

        Args:
            username: SSH username
            host: SSH host

        Returns:
            SSH password string or None if not needed
        """
        # Create a unique cache key
        cache_key = f"ssh:{username}@{host}"

        # Check cache first
        if cache_key in self._credential_cache:
            return self._credential_cache[cache_key]

        # Prompt for SSH password
        password = self._prompt_for_ssh_password(username, host)

        # Cache the password for this session
        if password:
            self._credential_cache[cache_key] = password

        return password

    def _prompt_for_ssh_password(self, username: str, host: str) -> Optional[str]:
        """Prompt user for SSH password."""
        if not sys.stdin.isatty():
            logger.error("Cannot prompt for SSH password: not running in a terminal")
            return None

        try:
            # Clear any Rich output and ensure clean terminal
            print("\r", end="", flush=True)
            prompt = f"Enter SSH password for {username}@{host}: "
            password = getpass.getpass(prompt)
            return password if password else None
        except (KeyboardInterrupt, EOFError):
            logger.info("SSH password prompt cancelled by user")
            return None
        except Exception as e:
            logger.error(f"Error prompting for SSH password: {e}")
            return None

    def try_ssh_agent_keys(
        self, username: str, host: str, port: int = 22
    ) -> Optional[paramiko.PKey]:
        """
        Try to authenticate using SSH agent keys.

        Args:
            username: SSH username
            host: SSH host
            port: SSH port

        Returns:
            SSH key if successful, None otherwise
        """
        if not self._ssh_agent_available:
            logger.debug("SSH agent not available")
            return None

        try:
            # Get keys from SSH agent
            agent = paramiko.Agent()
            agent_keys = agent.get_keys()

            if not agent_keys:
                logger.debug("No keys found in SSH agent")
                return None

            logger.debug(
                f"Testing {len(agent_keys)} SSH agent keys for {username}@{host}"
            )

            for i, key in enumerate(agent_keys):
                try:
                    # Create a temporary SSH client to test keys
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                    client.connect(
                        hostname=host,
                        port=port,
                        username=username,
                        pkey=key,
                        timeout=10,
                        look_for_keys=False,  # Don't look for local keys
                        allow_agent=True,  # Use agent
                    )

                    logger.debug(
                        f"SSH agent key #{i + 1} authentication successful for {username}@{host}"
                    )
                    client.close()
                    return key

                except paramiko.AuthenticationException:
                    logger.debug(f"SSH agent key #{i + 1} authentication failed")
                    continue
                except Exception as e:
                    logger.debug(f"SSH agent key #{i + 1} test failed: {e}")
                    continue

            logger.debug(f"All SSH agent keys failed for {username}@{host}")
            return None

        except Exception as e:
            logger.debug(f"SSH agent authentication failed: {e}")
            return None

    def load_private_key(
        self, key_path: str, username: str, host: str
    ) -> Optional[paramiko.PKey]:
        """
        Load private key with automatic passphrase prompting.

        Args:
            key_path: Path to the private key file
            username: SSH username
            host: SSH host

        Returns:
            Loaded SSH key or None if failed
        """
        try:
            # Expand user path
            key_path = os.path.expanduser(key_path)

            if not os.path.exists(key_path):
                logger.error(f"Private key not found: {key_path}")
                return None

            # Get passphrase if needed
            passphrase = self.get_private_key_passphrase(key_path, username, host)

            # Try to load key with different types
            for key_class in [
                paramiko.RSAKey,
                paramiko.Ed25519Key,
                paramiko.ECDSAKey,
                paramiko.DSSKey,
            ]:
                try:
                    if passphrase:
                        key = key_class.from_private_key_file(
                            key_path, password=passphrase
                        )
                    else:
                        key = key_class.from_private_key_file(key_path)

                    logger.debug(
                        f"Successfully loaded {key_class.__name__} from {key_path}"
                    )
                    return key

                except paramiko.PasswordRequiredException:
                    # Try next key type if no passphrase provided
                    if not passphrase:
                        continue
                    logger.error(f"Invalid passphrase for {key_path}")
                    return None
                except paramiko.SSHException:
                    # Try next key type
                    continue
                except Exception as e:
                    logger.debug(f"Failed to load key as {key_class.__name__}: {e}")
                    continue

            logger.error(f"Unable to load private key from {key_path}")
            return None

        except Exception as e:
            logger.error(f"Error loading private key {key_path}: {e}")
            return None

    def get_private_key_passphrase(
        self, key_path: str, username: str, host: str
    ) -> Optional[str]:
        """
        Get passphrase for private key, trying various methods.

        Args:
            key_path: Path to the private key file
            username: SSH username
            host: SSH host

        Returns:
            Passphrase string or None if not needed
        """
        # Create a unique cache key for this credential (key file path only)
        cache_key = f"passphrase:{key_path}"

        # Check cache first
        if cache_key in self._credential_cache:
            return self._credential_cache[cache_key]

        # Try to load key without passphrase first
        try:
            # Try different key types
            for key_class in [
                paramiko.RSAKey,
                paramiko.Ed25519Key,
                paramiko.ECDSAKey,
                paramiko.DSSKey,
            ]:
                try:
                    key_class.from_private_key_file(key_path)
                    logger.debug(f"Key {key_path} loaded without passphrase")
                    return None
                except paramiko.PasswordRequiredException:
                    # Key requires passphrase
                    break
                except paramiko.SSHException:
                    # Try next key type
                    continue

            # Key requires passphrase, prompt for it
            passphrase = self._prompt_for_passphrase(key_path, username, host)

            # Cache the passphrase for this session
            if passphrase:
                self._credential_cache[cache_key] = passphrase

            return passphrase

        except Exception as e:
            logger.error(f"Error checking key {key_path}: {e}")
            return None

    def _prompt_for_passphrase(
        self, key_path: str, username: str, host: str
    ) -> Optional[str]:
        """Prompt user for private key passphrase."""
        if not sys.stdin.isatty():
            logger.error("Cannot prompt for passphrase: not running in a terminal")
            return None

        try:
            # Clear any Rich output and ensure clean terminal
            print("\r", end="", flush=True)
            prompt = f"Enter passphrase for {key_path}: "
            passphrase = getpass.getpass(prompt)
            return passphrase if passphrase else None
        except (KeyboardInterrupt, EOFError):
            logger.info("Passphrase prompt cancelled by user")
            return None
        except Exception as e:
            logger.error(f"Error prompting for passphrase: {e}")
            return None

    def clear_cache(self):
        """Clear credential cache."""
        self._credential_cache.clear()
        logger.debug("Credential cache cleared")

    def is_ssh_agent_available(self) -> bool:
        """Check if SSH agent is available."""
        return self._ssh_agent_available


# Global credential manager instance
credential_manager = CredentialManager()
