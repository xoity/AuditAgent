# AuditAgent Examples

This directory contains example policies, device configurations, and scripts to help you get started with AuditAgent.

## Example Files

### Policy Examples

**`web-server-policy.yaml`**

- **Purpose**: Basic web server firewall policy
- **Features**: HTTP/HTTPS ingress, egress for updates, SSH management
- **Use Case**: Protecting a public-facing web server
- **Devices**: Single Linux server with iptables

**`simple-linux-policy.yaml`**

- **Purpose**: Minimal policy for testing
- **Features**: Basic HTTP/SSH rules, simple structure
- **Use Case**: Learning policy syntax, quick tests
- **Devices**: Single Linux device

**`clean-linux-policy.yaml`**

- **Purpose**: Production-ready secure policy
- **Features**: Comprehensive security rules, strict default-deny
- **Use Case**: Enterprise Linux server hardening
- **Devices**: Single Linux device with strict controls

### Device Configuration Examples

**`devices.yaml`**

- **Purpose**: Full-featured device configuration
- **Features**: SSH key authentication, multiple devices
- **Use Case**: Production multi-device deployments
- **Devices**: Multiple Linux servers with iptables

**`example-devices.yaml`**

- **Purpose**: Simple device configuration for testing
- **Features**: Single device, basic SSH settings
- **Use Case**: Quick testing, learning device configuration
- **Devices**: Single Linux device

### Python Scripts

**`example.py`**

- **Purpose**: Basic programmatic usage
- **Features**: Audit, enforcement, and remediation via Python API
- **Use Case**: Integrating AuditAgent into Python applications
- **Prerequisites**: AuditAgent installed via pip

**`linux_example.py`**

- **Purpose**: Linux-specific automation example
- **Features**: iptables-specific operations, advanced filtering
- **Use Case**: Linux-focused deployments, iptables management
- **Prerequisites**: Linux device with iptables

## Quick Start

### 1. Run a Basic Audit

```bash
# Audit a web server policy
audit-agent audit examples/web-server-policy.yaml examples/devices.yaml

# View detailed violations
audit-agent audit examples/web-server-policy.yaml examples/devices.yaml --verbose
```

### 2. Dry Run Enforcement

```bash
# See what changes would be made (safe, no actual changes)
audit-agent enforce examples/web-server-policy.yaml examples/devices.yaml

# With detailed output
audit-agent enforce examples/web-server-policy.yaml examples/devices.yaml --verbose
```

### 3. AI Remediation

```bash
# Generate AI-corrected policy (requires GOOGLE_AI_API_KEY)
export GOOGLE_AI_API_KEY="your-key-here"
audit-agent ai-remediate examples/web-server-policy.yaml examples/devices.yaml

# Review the generated policy
cat examples/web-server-policy-ai-remediation.yaml
```

## Example Use Cases

### Web Server Protection

**File**: `web-server-policy.yaml` + `devices.yaml`

```bash
# Audit compliance
audit-agent audit examples/web-server-policy.yaml examples/devices.yaml

# Apply the policy
audit-agent enforce examples/web-server-policy.yaml examples/devices.yaml --no-dry-run

# Verify enforcement
audit-agent audit examples/web-server-policy.yaml examples/devices.yaml
```

**Expected Result**: 100% compliance with HTTP/HTTPS open, all other inbound traffic blocked.

### Learning Policy Syntax

**File**: `simple-linux-policy.yaml`

```yaml
# Simple policy structure:
name: simple-linux
description: "Minimal policy for learning"
default_ingress_action: drop
default_egress_action: accept

rules:
  - name: "Allow SSH"
    direction: ingress
    protocol: tcp
    port: 22
    source: any
    destination: any
    action: accept
```

**Try**:

1. Copy this policy and modify it
2. Add your own rules
3. Test with `audit-agent audit`

### Programmatic Integration

**File**: `example.py`

```python
# Import AuditAgent modules
from audit_agent.core.policy import NetworkPolicy
from audit_agent.devices.linux_iptables import LinuxIptables
from audit_agent.audit.engine import AuditEngine
import asyncio

# Run audit programmatically
async def run_audit():
    policy = NetworkPolicy.from_yaml_file("examples/simple-linux-policy.yaml")
    device = LinuxIptables(host="192.168.1.10", username="admin")
    engine = AuditEngine()
    result = await engine.audit_policy(policy, [device])
    print(f"Compliance: {result.overall_compliance_percentage:.1f}%")

asyncio.run(run_audit())
```

## Common Workflows

### Workflow 1: New Policy Development

```bash
# Start with a simple policy
cp examples/simple-linux-policy.yaml my-policy.yaml

# Edit the policy
vim my-policy.yaml

# Test with audit (dry run, safe)
audit-agent audit my-policy.yaml examples/devices.yaml

# If issues found, use AI to fix
audit-agent ai-remediate my-policy.yaml examples/devices.yaml

# Apply when satisfied
audit-agent enforce my-policy.yaml examples/devices.yaml --no-dry-run
```

### Workflow 2: Multi-Device Deployment

```bash
# Create device list
cp examples/devices.yaml production-devices.yaml

# Edit to add your devices
vim production-devices.yaml

# Audit all devices
audit-agent audit examples/web-server-policy.yaml production-devices.yaml

# Apply to all devices
audit-agent enforce examples/web-server-policy.yaml production-devices.yaml --no-dry-run
```

### Workflow 3: Continuous Compliance

```bash
# Schedule regular audits (crontab)
0 */6 * * * audit-agent audit /path/to/policy.yaml /path/to/devices.yaml --output report.json

# Alert on compliance drops
audit-agent audit policy.yaml devices.yaml --min-compliance 95.0
```

## Customizing Examples

### Modify Policies

All policy files follow this structure:

```yaml
name: policy-name
description: "Policy description"
default_ingress_action: drop  # or accept
default_egress_action: accept  # or drop

rules:
  - name: "Rule description"
    direction: ingress  # or egress
    protocol: tcp  # tcp, udp, icmp, any
    port: 80  # or port range "80-443"
    source: any  # or CIDR "10.0.0.0/8"
    destination: any
    action: accept  # or drop
```

See [Configuration Guide](../docs/CONFIGURATION_GUIDE.md) for complete reference.

### Modify Device Configurations

Device files specify connection details:

```yaml
devices:
  - name: "web-server-1"
    type: "linux_iptables"
    host: "192.168.1.10"
    username: "admin"
    
    # SSH key authentication (recommended)
    private_key: "~/.ssh/id_rsa"
    
    # Or password (not recommended for production)
    # password: "secret"
    
    # Optional: SSH port
    port: 22
    
    # Optional: Connection timeout
    timeout: 30
```

See [Secure Authentication Guide](../docs/SECURE_AUTHENTICATION.md) for best practices.

## Testing Examples Locally

### Prerequisites

```bash
# Install AuditAgent
pip install audit-agent

# For AI features
export GOOGLE_AI_API_KEY="your-key"

# For SSH (if using key auth)
ssh-add ~/.ssh/id_rsa
```

### Local Testing with Docker

```bash
# Run a test Linux container with iptables
docker run -d --name test-firewall --cap-add=NET_ADMIN ubuntu:22.04 sleep infinity

# Get container IP
CONTAINER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' test-firewall)

# Update devices.yaml with container IP
# Then run audit/enforcement against the container
```

## Example Outputs

### Successful Audit (100% Compliant)

```
✓ Audit completed successfully
  Overall Compliance: 100.0%
  Compliant Devices: 1/1
  Total Issues: 0

Device Compliance:
  • web-server-1: 100.0% compliant
```

### Audit with Issues

```
✗ Audit found compliance issues
  Overall Compliance: 60.0%
  Compliant Devices: 0/1
  Total Issues: 4

Device Compliance:
  • web-server-1: 60.0% compliant (4 issues)

Issues by Severity:
  • HIGH: 2
  • MEDIUM: 2
```

### Enforcement Result

```
✓ Enforcement completed successfully
  Actions Executed: 4
  Successful: 4
  Failed: 0

Changes Applied:
  • Added rule: Allow HTTP (port 80)
  • Added rule: Allow HTTPS (port 443)
  • Modified default ingress action: drop
  • Modified default egress action: accept
```

## Support

- **Documentation**: See [docs/](../docs/) directory
- **Issues**: <https://github.com/xoity/AuditAgent/issues>
- **Examples**: This directory contains working examples
- **Community**: Discussions and contributions welcome!

## Next Steps

1. ✅ Review the example files in this directory
2. ✅ Copy an example policy and customize it for your needs
3. ✅ Test with `audit-agent audit` (safe, no changes)
4. ✅ Apply with `audit-agent enforce` when satisfied
5. ✅ Set up continuous compliance monitoring

**Ready to get started?** See the [Getting Started Guide](../docs/GETTING_STARTED.md)!
