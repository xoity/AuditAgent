# Getting Started with AuditAgent

AuditAgent is a comprehensive Python framework for declaratively defining and enforcing iptables firewall policies across Linux servers without requiring agents on the servers themselves.

## Quick Start

### 1. Installation

```bash
# Clone or navigate to the project directory
cd AuditAgent

# Install in development mode
pip install -e .

# Or install dependencies manually
pip install paramiko netmiko requests pydantic rich typer pyyaml jinja2 cryptography
```

### 2. Basic Usage

#### Create a Simple Policy

```python
from audit_agent import NetworkPolicy, FirewallRule

# Create a new policy
policy = NetworkPolicy("my-web-server-policy")

# Add a zone
dmz_zone = policy.add_zone("dmz")
dmz_zone.add_network("192.168.100.0/24")

# Add firewall rules using the fluent interface
ssh_rule = (FirewallRule()
            .allow_inbound()
            .tcp()
            .port(22)
            .from_ip("10.0.0.0/24")  # Management network
            .to_zone("dmz")
            .log()
            .priority_high())

ssh_rule.name = "allow-ssh-mgmt"
ssh_rule.description = "SSH access from management"
policy.add_firewall_rule(ssh_rule)

# Add web traffic rule
web_rule = (FirewallRule()
            .allow_inbound()
            .tcp()
            .ports([80, 443])
            .from_any()
            .to_zone("dmz"))

web_rule.name = "allow-web-traffic"
policy.add_firewall_rule(web_rule)

# Validate the policy
validation = policy.validate_policy()
if validation.is_valid:
    print("✓ Policy is valid!")
else:
    print("❌ Validation errors:", validation.errors)
```

#### Define Devices

```python
from audit_agent.devices import LinuxIptables

# Create device instances
server1 = LinuxIptables(
    host="192.168.1.10",
    username="admin",
    password="your_password",  # or use private_key instead
    sudo_password="sudo_password"  # optional if passwordless sudo
)

server2 = LinuxIptables(
    host="192.168.1.11", 
    username="admin",
    private_key="/path/to/private/key",  # SSH key authentication
    sudo_password="sudo_password"
)

devices = [server1, server2]
```

#### Audit Current State

```python
from audit_agent.audit import AuditEngine
import asyncio

async def run_audit():
    audit_engine = AuditEngine()
    result = await audit_engine.audit_policy(policy, devices)
    
    print(f"Compliance: {result.overall_compliance_percentage:.1f}%")
    print(f"Issues found: {result.total_issues}")
    
    # Generate detailed report
    report = audit_engine.generate_audit_report(result)
    print(report)

# Run the audit
asyncio.run(run_audit())
```

#### Enforce Policy (Dry Run)

```python
from audit_agent.enforcement import EnforcementEngine

async def run_enforcement():
    enforcement_engine = EnforcementEngine()
    
    # Dry run first
    result = await enforcement_engine.enforce_policy(policy, devices, dry_run=True)
    
    print(f"Planned actions: {result.total_actions_planned}")
    print(f"Success rate: {result.overall_success_rate:.1f}%")
    
    # Generate enforcement report
    report = enforcement_engine.generate_enforcement_report(result)
    print(report)

asyncio.run(run_enforcement())
```

### 3. Command Line Interface

#### Create Example Files

```bash
# Create example policy and device files
audit-agent create-example examples/my-policy.yaml

# This creates:
# - examples/my-policy.yaml (example policy)
# - You'll need to create devices.yaml manually
```

#### Audit Devices

```bash
# Audit devices against a policy
audit-agent audit examples/my-policy.yaml examples/devices.yaml

# Save report to file
audit-agent audit examples/my-policy.yaml examples/devices.yaml --output-file audit-report.txt

# Generate JSON report
audit-agent audit examples/my-policy.yaml examples/devices.yaml --output-format json
```

#### Enforce Policy

```bash
# Dry run (safe, shows what would change)
audit-agent enforce examples/my-policy.yaml examples/devices.yaml --dry-run

# Live enforcement (makes actual changes)
audit-agent enforce examples/my-policy.yaml examples/devices.yaml --no-dry-run
```

#### Validate Policy

```bash
# Validate policy syntax and logic
audit-agent validate examples/my-policy.yaml
```

### 4. Configuration Files

#### Policy File (YAML)

```yaml
metadata:
  name: "web-server-policy"
  version: "1.0"
  description: "Security policy for web servers"

zones:
  dmz:
    name: "dmz"
    description: "DMZ zone"
    networks:
      - cidr: "192.168.100.0/24"

firewall_rules:
  - id: "ssh-access"
    name: "allow-ssh-management"
    enabled: true
    priority: 10
    action: "allow"
    direction: "inbound"
    protocol:
      name: "tcp"
    source_ips:
      - cidr: "10.0.0.0/24"
    destination_zones:
      - name: "dmz"
    destination_ports:
      - number: 22
    log_traffic: true
```

#### Devices File (YAML)

```yaml
devices:
  - type: "linux_iptables"
    name: "web-server-01"
    host: "192.168.1.10"
    port: 22
    username: "admin"
    password: "your_password"
    sudo_password: "sudo_password"
    description: "Web server with iptables"

  - type: "linux_iptables"
    name: "web-server-02"
    host: "192.168.1.11"
    username: "admin"
    private_key: "/path/to/private/key"
    sudo_password: "sudo_password"
    description: "Backup web server with iptables"
```

### 5. Advanced Features

#### Custom Rule Types

```python
from audit_agent import NATRule, VPNRule, QoSRule

# NAT rule
nat_rule = NATRule(
    type="destination",
    original_ip=IPAddress(address="203.0.113.10"),
    translated_ip=IPAddress(address="192.168.100.10")
)
policy.add_nat_rule(nat_rule)

# QoS rule
qos_rule = QoSRule(
    traffic_class="critical",
    priority_level=1
).set_bandwidth("100Mbps")
policy.add_qos_rule(qos_rule)
```

#### Policy Validation

```python
# Comprehensive validation
validation = policy.validate_policy()

print("Errors:")
for error in validation.errors:
    print(f"  - {error}")

print("Warnings:")
for warning in validation.warnings:
    print(f"  - {warning}")
```

#### Export/Import

```python
# Export to different formats
yaml_content = policy.export_to_yaml()
json_content = policy.export_to_json()

# Import from files
policy_from_yaml = NetworkPolicy.from_yaml(yaml_content)
policy_from_json = NetworkPolicy.from_json(json_content)
```

## Examples

### Complete Example Script

See `examples/example.py` for a comprehensive demonstration of the framework's capabilities.

```bash
# Run the example
python examples/example.py
```

### Test the Framework

```bash
# Run basic functionality tests
python test_framework.py
```

## Supported Devices

Currently supported:

- Linux servers with iptables

Features:

- SSH authentication (password or private key)
- Sudo support for iptables commands
- IPv4 and IPv6 rules
- All standard iptables chains (INPUT, OUTPUT, FORWARD)
- NAT table support
- Rule validation and dry-run mode

## Key Features

1. **Declarative Policies**: Define what you want, not how to configure it
2. **Linux iptables Support**: Complete support for iptables firewall rules
3. **Audit & Compliance**: Compare actual vs. desired state
4. **Idempotent Enforcement**: Only make necessary changes
5. **Pre-flight Validation**: Simulate changes before applying
6. **Rich Reporting**: Detailed audit and enforcement reports
7. **Command Line Interface**: Easy to use CLI for operations
8. **Fluent API**: Intuitive rule building interface

## Security Considerations

- Always use dry-run mode first
- Store credentials securely (consider using environment variables)
- Backup device configurations before making changes
- Test policies in a lab environment first
- Monitor enforcement results carefully

## Contributing

The framework is designed to be extensible. To add support for new device types:

1. Inherit from `NetworkDevice` or `FirewallDevice`
2. Implement required abstract methods
3. Add device-specific command generation logic
4. Include configuration parsing logic

## Troubleshooting

### Connection Issues

- Verify device credentials
- Check network connectivity
- Ensure SSH is enabled on devices
- Verify privilege levels

### Policy Issues

- Use `audit-agent validate` to check syntax
- Review validation warnings
- Test with simple policies first

### Performance

- Use parallel processing for multiple devices
- Implement connection pooling for frequent operations
- Cache device configurations when appropriate
