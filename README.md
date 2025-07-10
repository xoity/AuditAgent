# AuditAgent - Linux iptables Policy Enforcer & Auditor

A Python framework for declaratively defining and enforcing iptables firewall policies across Linux servers without requiring agents on the servers themselves.

## Features

- **Declarative Policy Definition**: Define iptables policies using Python DSL
- **Linux iptables Support**: Complete support for iptables firewall rules
- **Policy Audit & Drift Detection**: Compare live iptables rules against declared policies
- **Idempotent Enforcement**: Apply changes only when needed
- **Pre-flight Validation**: Simulate changes before applying them
- **SSH Authentication**: Support for password and key-based authentication

## Quick Start

```python
from audit_agent import NetworkPolicy, FirewallRule, IPRange

# Define a security policy
policy = NetworkPolicy("production-web-servers")

# SSH access only from management subnets
policy.add_rule(
    FirewallRule()
    .allow_inbound()
    .port(22)
    .from_ip(IPRange("10.0.0.0/24"))  # Management subnet
    .to_zone("web-servers")
    .description("SSH access from management")
)

# Web traffic rules
policy.add_rule(
    FirewallRule()
    .allow_inbound()
    .ports([80, 443])
    .from_any()
    .to_zone("web-servers")
    .description("HTTP/HTTPS access")
)

# Apply policy to Linux servers
from audit_agent.devices import LinuxIptables

devices = [
    LinuxIptables("192.168.1.10", username="admin", password="secret"),
    LinuxIptables("192.168.1.11", username="admin", private_key="/path/to/key")
]

# Audit current state
audit_results = policy.audit(devices)
print(f"Policy compliance: {audit_results.compliance_percentage}%")

# Apply changes if needed
if not audit_results.is_compliant:
    policy.enforce(devices, dry_run=True)  # Simulate first
    policy.enforce(devices)  # Apply changes
```

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

## License

MIT License
