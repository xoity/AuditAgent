# AuditAgent - Linux iptables Policy Enforcer & Auditor [![PyPI version](https://img.shields.io/pypi/v/auditagent)](https://pypi.org/project/auditagent/) [![License](https://img.shields.io/github/license/xoity/AuditAgent)](LICENSE) [![Build Status](https://img.shields.io/github/actions/workflow/status/xoity/AuditAgent/ci.yml?branch=main)](https://github.com/xoity/AuditAgent/actions)

- A Python framework for declaratively defining and enforcing iptables firewall policies across Linux servers without requiring agents on the servers themselves.

## Table of Contents

- [Features](#features)
- [Getting Started](#getting-started)
- [Configuration Guide](#configuration-guide)
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
- **Idempotent Enforcement**: Apply changes only when needed
- **Pre-flight Validation**: Simulate changes before applying them
- **SSH Authentication**: Support for password and key-based authentication

## Getting Started

Refer to the [Getting Started guide](GETTING_STARTED.md) for installation steps, example code, and CLI usage.

## Configuration Guide

For detailed YAML schema and reference, see the [Configuration Guide](CONFIGURATION_GUIDE.md).

## Examples

The `examples/` directory contains sample policy and device configurations:

- **simple-linux-policy.yaml**: Minimal policy example
- **devices.yaml**: Sample device inventory configuration
- **web-server-policy.yaml**: End-to-end web server policy
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
