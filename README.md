# AuditAgent - Linux iptables Policy Enforcer & Auditor [![PyPI version](https://img.shields.io/pypi/v/auditagent)](https://pypi.org/project/audit-agent/) [![License](https://img.shields.io/github/license/xoity/AuditAgent)](LICENSE) [![Build Status](https://img.shields.io/github/actions/workflow/status/xoity/AuditAgent/ci.yml?branch=main)](https://github.com/xoity/AuditAgent/actions)

- A Python framework for declaratively defining and enforcing iptables firewall policies across Linux servers without requiring agents on the servers themselves.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
- [Automated Remediation](#automated-remediation)
- [Deterministic Sandbox Testing](#deterministic-sandbox-testing)
- [Configuration Guide](#configuration-guide)
- [Secure Authentication](#secure-authentication)
- [Examples](#examples)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Supported Devices](#supported-devices)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Declarative Policy Definition**: Define iptables policies using Python DSL
- **Linux iptables Support**: Complete support for iptables firewall rules
- **Policy Audit & Drift Detection**: Compare live iptables rules against declared policies
- **🤖 AI-Powered Remediation**: Automatically generate remediation policies using Google AI or OpenAI
- **Automated Remediation**: Intelligent automated fixing of detected policy violations
- **Risk-Based Strategies**: Conservative, balanced, and aggressive remediation approaches
- **Rollback Capabilities**: Automatic rollback on validation failures
- **Idempotent Enforcement**: Apply changes only when needed
- **Pre-flight Validation**: Simulate changes before applying them
- **Secure Authentication**: Dynamic credential prompting and SSH agent integration
- **SSH Authentication**: Support for password and key-based authentication

## Getting Started

Refer to the [Getting Started guide](docs/GETTING_STARTED.md) for installation steps, example code, and CLI usage.

### Verification Workflow

End-to-end live test against an Alpine Linux VM showing audit, dry-run, enforcement, and verification:

```bash
# 1. Create policy (allow SSH, HTTP; block telnet)
cat > policy.yaml << 'EOF'
metadata:
  name: "vm-policy"
  version: "1.0"
  description: "Test policy for SSH + HTTP"
firewall_rules:
  - name: "allow-ssh"
    enabled: true
    priority: 10
    action: "allow"
    direction: "inbound"
    protocol: { name: "tcp", number: 6 }
    destination_ports: [{ number: 22 }]
  - name: "allow-http"
    enabled: true
    priority: 20
    action: "allow"
    direction: "inbound"
    protocol: { name: "tcp", number: 6 }
    destination_ports: [{ number: 80 }]
  - name: "block-telnet"
    enabled: true
    priority: 50
    action: "deny"
    direction: "inbound"
    protocol: { name: "tcp", number: 6 }
    destination_ports: [{ number: 23 }]
    log_traffic: true
EOF

# 2. Create devices config (VM at 127.0.0.1:2200)
cat > devices.yaml << 'EOF'
devices:
  - type: "linux_iptables"
    name: "test-vm"
    host: "127.0.0.1"
    port: 2200
    username: "vagrant"
EOF

# 3. Audit current state
audit-agent audit policy.yaml devices.yaml --full-report
# Output: 0% compliance, 3 rules missing

# 4. Dry-run enforce (validates commands, no changes)
audit-agent enforce --dry-run policy.yaml devices.yaml
# Output: 3 actions planned, all validated

# 5. Live enforce (applies rules)
audit-agent enforce --no-dry-run policy.yaml devices.yaml
# Output: 3 actions executed, 3 success, 0 fail

# 6. Verify iptables on the device
ssh vagrant@127.0.0.1 -p 2200 "sudo iptables -L -n"
# Shows: ACCEPT tcp dpt:22, ACCEPT tcp dpt:80, LOG+DROP tcp dpt:23

# 7. Re-audit to confirm 100% compliance
audit-agent audit policy.yaml devices.yaml
# Output: 100% compliance, 0 issues
```

> **Note on SSH keys**: If SSH agent is available (e.g. `vagrant ssh` sets it up), omit `private_key` from devices config. The SSH agent provides keys automatically, avoiding permission warnings on key files owned by root/Vagrant.

## AI-Powered Remediation 🤖

AuditAgent now includes AI-powered automatic remediation that uses advanced language models to analyze compliance issues and generate corrected policies:

```bash
# Set your Google AI Studio API key (free tier available)
export GOOGLE_AI_API_KEY="your-key-here"

# Generate and apply AI-powered remediation
audit-agent ai-remediate policy.yaml devices.yaml --apply
```

**Features:**

- 🎯 Achieves 100% compliance automatically
- 🔄 Iterative refinement for optimal results
- 📊 Detailed analysis and summary reports
- 🌐 Supports Google AI Studio (Gemini), OpenAI, Azure OpenAI
- 🔒 Secure local API key management
- 🚀 Designed for future web-based management

For complete documentation, see [AI Remediation Guide](docs/AI_REMEDIATION.md).

## Automated Remediation

AuditAgent now supports intelligent automated remediation that can fix detected policy violations without manual intervention. This feature provides:

- **Smart Decision Making**: Risk-based analysis of whether violations should be automatically fixed
- **Multiple Strategies**: Choose from conservative, balanced, or aggressive remediation approaches
- **Safety First**: Dry-run by default with explicit confirmation for risky changes
- **Rollback Protection**: Automatic rollback if validation fails after remediation
- **Comprehensive Reporting**: Detailed logs of all remediation actions taken

### Quick Start

```bash
# Dry-run automated remediation (safe, shows what would be done)
audit-agent auto-remediate --devices devices.yaml --policy policy.yaml

# Execute remediation with conservative strategy
audit-agent auto-remediate --devices devices.yaml --policy policy.yaml --execute --strategy conservative

# View detailed help
audit-agent auto-remediate --help
```

For complete documentation, see [Automated Remediation Guide](docs/AUTOMATED_REMEDIATION.md).

## Deterministic Sandbox Testing

Use the persistent sandbox backend for repeatable audit/enforce tests without a VM, SSH target, or local firewall changes.

```bash
# reset sandbox state
rm -f .audit-agent/sandbox-42.json

# run against the deterministic sandbox
audit-agent audit examples/simple-linux-policy.yaml examples/sandbox-devices.yaml
audit-agent enforce --dry-run examples/simple-linux-policy.yaml examples/sandbox-devices.yaml
audit-agent enforce --no-dry-run examples/simple-linux-policy.yaml examples/sandbox-devices.yaml

# verify idempotency
audit-agent enforce --no-dry-run examples/simple-linux-policy.yaml examples/sandbox-devices.yaml
```

What this gives you:

- `audit` starts with missing rules and shows drift
- `--dry-run` validates planned changes without mutating sandbox state
- live `enforce` applies changes to the persistent sandbox file
- a second live `enforce` stays clean and creates no duplicate rules
- rollback is covered by the test suite through a forced failure path

Run the dedicated test:

```bash
rtk pytest tests/test_sandbox_enforcement.py -vv
```

Run the full suite:

```bash
rtk pytest tests -vv
```

## Configuration Guide

For detailed YAML schema and reference, see the [Configuration Guide](docs/CONFIGURATION_GUIDE.md).

## Secure Authentication

AuditAgent supports secure authentication without hardcoded credentials. See the [Secure Authentication Guide](docs/SECURE_AUTHENTICATION.md) for:

- **SSH Agent Integration**: Use SSH agent for key management
- **Dynamic Credential Prompting**: Prompt for passwords at runtime
- **Migration from Hardcoded Credentials**: Remove security risks from config files

Quick example:

```yaml
devices:
  - type: "linux_iptables"
    name: "web-server-01"
    host: "192.168.0.111"
    username: "vagrant"
    private_key: "~/.ssh/id_rsa"
    # No hardcoded passwords - prompts when needed
```

## Examples

The `examples/` directory contains sample policy and device configurations:

- **simple-linux-policy.yaml**: Minimal policy example
- **devices.yaml**: Sample device inventory configuration
- **devices-secure.yaml**: Secure device configuration without hardcoded credentials
- **web-server-policy.yaml**: End-to-end web server policy
- **automated_remediation_demo.py**: Demonstrates automated remediation features
- See additional configurations in the [examples/](examples/) folder.

## Installation

### Standard Installation

```bash
pip install audit-agent
```

### With AI Support

```bash
pip install audit-agent[ai]
```

Or install from source:

```bash
git clone https://github.com/xoity/AuditAgent
cd AuditAgent
pip install -e ".[ai]"
```

## Project Structure

``` plaintext
audit_agent/
├── core/           # Core policy and rule definitions
├── devices/        # Linux iptables implementation
├── audit/          # Audit and compliance checking
├── enforcement/    # Policy enforcement engine
├── validation/     # Pre-flight checks and validation
└── utils/          # Utilities and helpers
```

## Supported Devices

- Linux servers with iptables firewall

## Contributing

Contributions, issues, and feature requests are welcome. Please open an issue or pull request on the [GitHub repository](https://github.com/xoity/AuditAgent).

## License

MIT License
