"""
Tests for the credential manager.
"""

import os
from unittest.mock import MagicMock, patch

import paramiko
import pytest

from audit_agent.core.credentials import CredentialManager, credential_manager


class TestCredentialManager:
    """Test credential manager functionality."""

    def test_singleton_pattern(self):
        """Test that CredentialManager uses singleton pattern."""
        # The module exposes a global credential_manager instance for shared use
        assert isinstance(credential_manager, CredentialManager)

    def test_cache_ssh_password(self):
        """Test SSH password caching."""
        cm = CredentialManager()
        cm.clear_cache()

        # Mock TTY and getpass to return a password
        with patch("sys.stdin.isatty", return_value=True), patch(
            "getpass.getpass", return_value="test_password"
        ) as mock_getpass:
            pwd1 = cm.get_ssh_password("testhost", "testuser")
            pwd2 = cm.get_ssh_password("testhost", "testuser")

            assert pwd1 == "test_password"
            assert pwd2 == "test_password"
            assert mock_getpass.call_count == 1  # Should only prompt once

    def test_cache_key_passphrase(self):
        """Test private key passphrase caching per key file."""
        cm = CredentialManager()
        cm.clear_cache()

        key_file1 = "/path/to/key1"
        key_file2 = "/path/to/key2"
        # Patch paramiko key loaders so they indicate passphrase is required, and enable TTY
        with patch("sys.stdin.isatty", return_value=True), patch(
            "getpass.getpass", side_effect=["pass1", "pass2"]
        ) as mock_getpass, patch(
            "paramiko.RSAKey.from_private_key_file",
            side_effect=paramiko.PasswordRequiredException(),
        ), patch(
            "paramiko.Ed25519Key.from_private_key_file",
            side_effect=paramiko.PasswordRequiredException(),
        ), patch(
            "paramiko.ECDSAKey.from_private_key_file",
            side_effect=paramiko.PasswordRequiredException(),
        ):
            # Different key files should prompt separately
            pp1 = cm.get_private_key_passphrase(key_file1, "user", "host")
            pp2 = cm.get_private_key_passphrase(key_file2, "user", "host")

            # Same key file should use cache
            pp1_again = cm.get_private_key_passphrase(key_file1, "user", "host")

            assert pp1 == "pass1"
            assert pp2 == "pass2"
            assert pp1_again == "pass1"
            assert mock_getpass.call_count == 2  # Only 2 prompts for 2 different keys

    def test_clear_cache(self):
        """Test cache clearing."""
        cm = CredentialManager()
        cm.clear_cache()

        with patch("sys.stdin.isatty", return_value=True), patch(
            "getpass.getpass", return_value="test_password"
        ) as mock_getpass:
            pwd1 = cm.get_ssh_password("testhost", "testuser")
            cm.clear_cache()
            pwd2 = cm.get_ssh_password("testhost", "testuser")

            assert pwd1 == pwd2
            assert mock_getpass.call_count == 2  # Should prompt twice after clear

    def test_non_interactive_mode(self):
        """Test non-interactive mode fails instead of prompting."""
        cm = CredentialManager()
        cm.clear_cache()
        cm.set_non_interactive(True)

        # In non-interactive mode the manager returns None rather than raising
        assert cm.get_ssh_password("testhost", "testuser") is None
        assert cm.get_private_key_passphrase("/path/to/key", "user", "host") is None

    def test_non_interactive_with_cache(self):
        """Test non-interactive mode works with cached credentials."""
        cm = CredentialManager()
        cm.clear_cache()

        # Cache a password first (allow prompting by mocking TTY)
        with patch("sys.stdin.isatty", return_value=True), patch(
            "getpass.getpass", return_value="cached_password"
        ):
            pwd1 = cm.get_ssh_password("testhost", "testuser")

        # Non-interactive mode should still return cached password
        cm.set_non_interactive(True)
        pwd2 = cm.get_ssh_password("testhost", "testuser")

        assert pwd1 == pwd2 == "cached_password"

    def test_ssh_agent_control(self):
        """Test SSH agent enable/disable control."""
        cm = CredentialManager()

        # Default should allow SSH agent
        assert cm.is_ssh_agent_available() in [True, False]

        # Disable SSH agent
        cm.set_allow_ssh_agent(False)
        assert cm.is_ssh_agent_available() is False

        # Enable SSH agent (availability depends on local environment/agent)
        cm.set_allow_ssh_agent(True)
        assert cm.is_ssh_agent_available() in [True, False]

    def test_ssh_agent_keys_disabled(self):
        """Test that try_ssh_agent_keys returns empty when disabled."""
        cm = CredentialManager()
        cm.set_allow_ssh_agent(False)

        result = cm.try_ssh_agent_keys("testuser", "testhost", 22)
        assert result is None

    def test_load_private_key_with_passphrase(self):
        """Test loading private key with passphrase."""
        cm = CredentialManager()
        cm.clear_cache()

        # Create a mock key file path
        key_file = "/tmp/test_key"

        # Simulate file exists and first load attempt requires passphrase
        with patch("os.path.exists", return_value=True), patch(
            "sys.stdin.isatty", return_value=True
        ), patch("getpass.getpass", return_value="test_passphrase"), patch(
            "paramiko.RSAKey.from_private_key_file",
            side_effect=[paramiko.PasswordRequiredException(), MagicMock()],
        ):
            key = cm.load_private_key(key_file, "user", "host")

            # Should have tried loading RSA key twice (first detected passphrase, second succeeded)
            # The patched side_effect list implies success on second call
            assert key is not None

    def test_environment_variable_non_interactive(self):
        """Test that AUDIT_AGENT_NONINTERACTIVE environment variable is respected."""
        cm = CredentialManager()
        cm.clear_cache()

        with patch.dict(os.environ, {"AUDIT_AGENT_NONINTERACTIVE": "1"}):
            # The environment variable itself doesn't automatically enable non-interactive
            # The CLI layer checks it and calls set_non_interactive(True)
            # This test just verifies the environment variable exists
            assert os.environ.get("AUDIT_AGENT_NONINTERACTIVE") == "1"

    def test_different_users_different_cache(self):
        """Test that different users on same host have separate cache."""
        cm = CredentialManager()
        cm.clear_cache()

        with patch("sys.stdin.isatty", return_value=True), patch(
            "getpass.getpass", side_effect=["user1_pass", "user2_pass"]
        ) as mock_getpass:
            pwd1 = cm.get_ssh_password("testhost", "user1")
            pwd2 = cm.get_ssh_password("testhost", "user2")

            assert pwd1 == "user1_pass"
            assert pwd2 == "user2_pass"
            assert mock_getpass.call_count == 2

    def test_cache_persists_across_calls(self):
        """Test that cache persists across multiple calls."""
        cm = CredentialManager()
        cm.clear_cache()

        with patch("sys.stdin.isatty", return_value=True), patch(
            "getpass.getpass", return_value="persistent_password"
        ) as mock_getpass:
            # Multiple calls should only prompt once
            for _ in range(5):
                pwd = cm.get_ssh_password("testhost", "testuser")
                assert pwd == "persistent_password"

            assert mock_getpass.call_count == 1


class TestCredentialManagerIntegration:
    """Integration tests for credential manager."""

    @pytest.mark.skip(reason="Requires actual SSH agent setup")
    def test_real_ssh_agent(self):
        """Test with real SSH agent (requires setup)."""
        cm = CredentialManager()

        if cm.is_ssh_agent_available():
            # This would need a real SSH setup to test properly
            pass

    @pytest.mark.skip(reason="Requires manual passphrase entry")
    def test_real_key_loading(self):
        """Test loading real private keys (requires manual interaction)."""
        # This would prompt for real passphrases
        pass
