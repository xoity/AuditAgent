#!/usr/bin/env python3
"""
Quick test of credential prompting functionality.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "."))

from audit_agent.core.credentials import credential_manager


def test_prompts():
    """Test credential prompting manually."""
    print("Testing AuditAgent Credential Prompting")
    print("=" * 45)

    print("\nSSH Agent Status:")
    print(f"  SSH_AUTH_SOCK: {os.environ.get('SSH_AUTH_SOCK', 'Not set')}")
    print(f"  Agent available: {credential_manager.is_ssh_agent_available()}")

    print("\nTesting credential prompting (you can cancel with Ctrl+C):")

    try:
        # Test passphrase prompt
        print("\n1. Testing passphrase prompt...")
        passphrase = credential_manager.get_private_key_passphrase(
            "/home/xoity/.ssh/id_rsa", "vagrant", "192.168.0.111"
        )
        if passphrase:
            print("   ✓ Passphrase received (hidden)")
        else:
            print("   ✓ No passphrase needed or cancelled")

    except KeyboardInterrupt:
        print("\n   ✓ Cancelled by user")

    try:
        # Test sudo password prompt
        print("\n2. Testing sudo password prompt...")
        sudo_pass = credential_manager.get_sudo_password("vagrant", "192.168.0.111")
        if sudo_pass:
            print("   ✓ Sudo password received (hidden)")
        else:
            print("   ✓ No sudo password or cancelled")

    except KeyboardInterrupt:
        print("\n   ✓ Cancelled by user")

    print("\n" + "=" * 45)
    print("Credential prompting test completed!")


if __name__ == "__main__":
    test_prompts()
