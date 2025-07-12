# AuditAgent - Linux iptables Policy Enforcer & Auditor [![PyPI version](https://img.shields.io/pypi/v/auditagent)](https://pypi.org/project/auditagent/) [![License](https://img.shields.io/github/license/xoity/AuditAgent)](LICENSE) [![Build Status](https://img.shields.io/github/actions/workflow/status/xoity/AuditAgent/ci.yml?branch=main)](https://github.com/xoity/AuditAgent/actions)

- A Python framework for declaratively defining and enforcing iptables firewall policies across Linux servers without requiring agents on the servers themselves.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
- [Automated Remediation](#automated-remediation)
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
- **Automated Remediation**: Intelligent automated fixing of detected policy violations
- **Risk-Based Strategies**: Conservative, balanced, and aggressive remediation approaches
- **Rollback Capabilities**: Automatic rollback on validation failures
- **Idempotent Enforcement**: Apply changes only when needed
- **Pre-flight Validation**: Simulate changes before applying them
- **Secure Authentication**: Dynamic credential prompting and SSH agent integration
- **SSH Authentication**: Support for password and key-based authentication

## Getting Started

Refer to the [Getting Started guide](docs/GETTING_STARTED.md) for installation steps, example code, and CLI usage.

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

```bash
pip install -e .
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
