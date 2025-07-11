# Secure Authentication Guide

This guide explains how to use AuditAgent's secure authentication features to avoid hardcoding credentials in configuration files.

## Overview

AuditAgent now supports dynamic credential prompting and SSH agent integration, eliminating the need to store passwords and private key passphrases in plain text configuration files.

## Authentication Methods (in order of preference)

### 1. SSH Agent Authentication (Recommended)

AuditAgent will automatically try SSH agent keys first if available:

```bash
# Start SSH agent if not running
eval "$(ssh-agent -s)"

# Add your keys
ssh-add ~/.ssh/id_rsa
ssh-add ~/.ssh/id_ed25519

# Run AuditAgent - it will use SSH agent automatically
python -m audit_agent.cli audit policy.yaml devices.yaml
```

### 2. Private Key with Dynamic Passphrase Prompting

If SSH agent is not available, AuditAgent will prompt for passphrases:

```yaml
devices:
  - type: "linux_iptables"
    name: "web-server-01"
    host: "192.168.0.111"
    username: "vagrant"
    private_key: "~/.ssh/id_rsa"
    # No passphrase field - will prompt when needed
```

When you run AuditAgent, you'll see:
```
Enter passphrase for /home/user/.ssh/id_rsa: [hidden input]
Enter sudo password for vagrant@192.168.0.111: [hidden input]
```

### 3. Password Authentication with Dynamic Prompting

For systems without SSH keys:

```yaml
devices:
  - type: "linux_iptables"
    name: "web-server-01"
    host: "192.168.0.111"
    username: "vagrant"
    # No password field - will prompt when needed
```

## Security Best Practices

### ✅ Recommended Configuration

```yaml
devices:
  - type: "linux_iptables"
    name: "web-server-01"
    host: "192.168.0.111"
    username: "vagrant"
    private_key: "~/.ssh/id_rsa"
    description: "Primary web server"
```

### ❌ Deprecated (Security Risk)

```yaml
devices:
  - type: "linux_iptables"
    name: "web-server-01"
    host: "192.168.0.111"
    username: "vagrant"
    private_key: "~/.ssh/id_rsa"
    private_key_passphrase: "secret123"  # ❌ Security risk
    sudo_password: "admin123"            # ❌ Security risk
```

## Advanced Features

### Credential Caching

Credentials are cached for the session to avoid repeated prompts:

```bash
# First connection prompts for credentials
python -m audit_agent.cli audit policy.yaml devices.yaml
Enter passphrase for /home/user/.ssh/id_rsa: [hidden input]
Enter sudo password for vagrant@192.168.0.111: [hidden input]

# Subsequent operations use cached credentials
python -m audit_agent.cli enforce policy.yaml devices.yaml
# No prompts - uses cached credentials
```

### SSH Agent Forwarding

For remote operations through jump hosts:

```bash
# Connect with agent forwarding
ssh -A jumphost.example.com

# Run AuditAgent on jump host
python -m audit_agent.cli audit policy.yaml devices.yaml
```

### Environment Variables (CI/CD)

For automated environments, you can still use environment variables:

```bash
# Set environment variables
export AUDIT_AGENT_SSH_PASSWORD="secret"
export AUDIT_AGENT_SUDO_PASSWORD="admin"

# Run AuditAgent
python -m audit_agent.cli audit policy.yaml devices.yaml
```

## Migration from Hardcoded Credentials

### Step 1: Remove Hardcoded Credentials

Remove these fields from your `devices.yaml`:
- `password`
- `private_key_passphrase`
- `sudo_password`

### Step 2: Set Up SSH Agent (Recommended)

```bash
# Start SSH agent
eval "$(ssh-agent -s)"

# Add your keys
ssh-add ~/.ssh/id_rsa

# Verify keys are loaded
ssh-add -l
```

### Step 3: Test Connection

```bash
# Test with dry run first
python -m audit_agent.cli audit policy.yaml devices.yaml --dry-run
```

## Troubleshooting

### SSH Agent Not Working

```bash
# Check if agent is running
echo $SSH_AUTH_SOCK

# Check loaded keys
ssh-add -l

# Restart agent if needed
pkill ssh-agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_rsa
```

### Permission Errors

```bash
# Fix key permissions
chmod 600 ~/.ssh/id_rsa
chmod 700 ~/.ssh
```

### Connection Timeouts

Increase timeout in devices.yaml:
```yaml
connection_settings:
  timeout: 60  # Increase from default 30
```

## Backward Compatibility

- Existing configurations with hardcoded credentials will continue to work
- Deprecation warnings will be shown when hardcoded credentials are detected
- Migration guide provided for removing hardcoded credentials

## Examples

See `examples/devices-secure.yaml` for a complete example of secure device configuration.
