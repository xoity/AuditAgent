# AuditAgent Configuration Guide

This guide covers how to write device configuration files (`devices.yaml`) and security policy files (`policy.yaml`) for the AuditAgent network security tool.

## Table of Contents

1. [Device Configuration Files](#device-configuration-files)
2. [Security Policy Files](#security-policy-files)
3. [Complete Examples](#complete-examples)
4. [Best Practices](#best-practices)
5. [Troubleshooting](#troubleshooting)

---

## Device Configuration Files

Device configuration files define the network devices that AuditAgent will audit and enforce policies on. They contain connection information, credentials, and device-specific settings.

### Basic Structure

```yaml
devices:
  - type: "device_type"
    name: "device_name"
    host: "ip_address_or_hostname"
    # Additional device-specific configuration
```

### Supported Device Types

#### Linux IPTables (`linux_iptables`)

For Linux servers using iptables firewall:

```yaml
devices:
  - type: "linux_iptables"
    name: "web-server-01"
    host: "192.168.1.100"
    port: 22                              # SSH port (optional, default: 22)
    username: "admin"                     # SSH username
    private_key: "/path/to/private/key"   # SSH private key path
    sudo_password: "password"             # Sudo password for privilege escalation
    description: "Primary web server"     # Optional description
```

### Authentication Methods

#### SSH Key Authentication (Recommended)

```yaml
devices:
  - type: "linux_iptables"
    name: "server-01"
    host: "192.168.1.100"
    username: "admin"
    private_key: "/home/user/.ssh/id_rsa"
    sudo_password: "admin_password"
```

**Important Notes:**

- If your SSH key has a passphrase, AuditAgent will NOT prompt you interactively, you must add `private_key_passphrase` to the config file.
- Do NOT include `private_key_passphrase` in the config file for security
- Ensure the private key file has proper permissions (600)

#### Password Authentication (Not Recommended)

```yaml
devices:
  - type: "linux_iptables"
    name: "server-01"
    host: "192.168.1.100"
    username: "admin"
    password: "ssh_password"
    sudo_password: "admin_password"
```

### Device Configuration Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Device type (`linux_iptables`) |
| `name` | string | Yes | Unique device identifier |
| `host` | string | Yes | IP address or hostname |
| `port` | integer | No | SSH port (default: 22) |
| `username` | string | Yes | SSH username |
| `password` | string | No | SSH password (use key auth instead) |
| `private_key` | string | No | Path to SSH private key |
| `sudo_password` | string | Yes | Password for sudo operations |
| `description` | string | No | Human-readable description |

### Multiple Devices Example

```yaml
devices:
  # Production web server
  - type: "linux_iptables"
    name: "web-prod-01"
    host: "10.0.1.10"
    username: "admin"
    private_key: "/home/user/.ssh/prod_key"
    sudo_password: "prod_admin_pass"
    description: "Production web server"
  
  # Development server
  - type: "linux_iptables"
    name: "web-dev-01"
    host: "192.168.1.20"
    username: "developer"
    private_key: "/home/user/.ssh/dev_key"
    sudo_password: "dev_admin_pass"
    description: "Development web server"
  
  # Database server
  - type: "linux_iptables"
    name: "db-prod-01"
    host: "10.0.2.10"
    username: "dbadmin"
    private_key: "/home/user/.ssh/db_key"
    sudo_password: "db_admin_pass"
    description: "Production database server"
```

---

## Security Policy Files

Security policy files define the desired network security configuration that devices should comply with. They specify firewall rules, network zones, and global settings.

### Basic Structure

```yaml
metadata:
  name: "policy_name"
  version: "1.0"
  description: "Policy description"
  author: "Author Name"

zones:
  zone_name:
    name: "zone_name"
    description: "Zone description"
    networks:
      - cidr: "network_cidr"

firewall_rules:
  - name: "rule_name"
    description: "Rule description"
    # Rule configuration...

# Optional sections
nat_rules: []
global_settings: {}
```

### Metadata Section

```yaml
metadata:
  name: "web-server-policy"          # Policy identifier
  version: "1.2"                     # Version number
  description: "Web server security policy"
  author: "Security Team"            # Author information
  created_date: "2025-01-15"        # Creation date
  tags: ["web", "production"]       # Optional tags
```

### Network Zones

Zones define logical network segments:

```yaml
zones:
  dmz:
    name: "dmz"
    description: "DMZ network for web servers"
    networks:
      - cidr: "192.168.100.0/24"
      - cidr: "192.168.101.0/24"
  
  internal:
    name: "internal"
    description: "Internal corporate network"
    networks:
      - cidr: "10.0.0.0/8"
      - cidr: "172.16.0.0/12"
  
  management:
    name: "management"
    description: "Network management subnet"
    networks:
      - cidr: "192.168.1.0/24"
```

### Firewall Rules

#### Basic Rule Structure

```yaml
firewall_rules:
  - name: "rule_name"              # Required: Unique rule identifier
    description: "Rule description" # Optional: Human-readable description
    enabled: true                  # Required: Enable/disable rule
    priority: 10                   # Required: Rule priority (lower = higher priority)
    action: "allow"                # Required: "allow" or "deny"
    direction: "inbound"           # Required: "inbound", "outbound", or "both"
    protocol:                      # Required: Protocol specification
      name: "tcp"                  # Protocol name: "tcp", "udp", "icmp", "any"
      number: 6                    # Optional: Protocol number
    # Source and destination specifications...
    log_traffic: false             # Optional: Enable logging for this rule
    tags: ["web", "public"]        # Optional: Tags for organization
```

#### Source and Destination Specification

You can specify sources and destinations using IP addresses, IP ranges, or zones:

**By IP Address/Range:**

```yaml
source_ips:
  - cidr: "0.0.0.0/0"           # Any source
  - cidr: "192.168.1.0/24"      # Specific subnet
  - cidr: "10.0.0.1/32"         # Single IP

destination_ips:
  - cidr: "192.168.100.10/32"   # Specific server
```

**By Zone:**

```yaml
source_zones:
  - name: "management"

destination_zones:
  - name: "dmz"
```

**Port Specifications:**

```yaml
source_ports:
  - number: 1024                 # Single port
  - range_start: 1024           # Port range
    range_end: 65535

destination_ports:
  - number: 22                   # SSH
  - number: 80                   # HTTP
  - number: 443                  # HTTPS
```

#### Common Rule Examples

**SSH Access from Management Network:**

```yaml
- name: "allow-ssh-management"
  description: "Allow SSH access from management network"
  enabled: true
  priority: 10
  action: "allow"
  direction: "inbound"
  protocol:
    name: "tcp"
    number: 6
  source_zones:
    - name: "management"
  destination_zones:
    - name: "dmz"
  destination_ports:
    - number: 22
  log_traffic: true
```

**Web Traffic from Internet:**

```yaml
- name: "allow-web-public"
  description: "Allow HTTP/HTTPS from anywhere"
  enabled: true
  priority: 20
  action: "allow"
  direction: "inbound"
  protocol:
    name: "tcp"
  source_ips:
    - cidr: "0.0.0.0/0"
  destination_zones:
    - name: "dmz"
  destination_ports:
    - number: 80
    - number: 443
  log_traffic: false
```

**Database Access (Outbound):**

```yaml
- name: "allow-database-access"
  description: "Allow access to internal databases"
  enabled: true
  priority: 30
  action: "allow"
  direction: "outbound"
  protocol:
    name: "tcp"
  source_zones:
    - name: "dmz"
  destination_zones:
    - name: "internal"
  destination_ports:
    - number: 3306   # MySQL
    - number: 5432   # PostgreSQL
  log_traffic: true
```

**Block Malicious Traffic:**

```yaml
- name: "block-malicious-ips"
  description: "Block known malicious IP ranges"
  enabled: true
  priority: 5      # High priority (processed early)
  action: "deny"
  direction: "inbound"
  protocol:
    name: "any"
  source_ips:
    - cidr: "203.0.113.0/24"    # Known bad subnet
    - cidr: "198.51.100.0/24"   # Another bad subnet
  destination_zones:
    - name: "dmz"
  log_traffic: true
```

**Default Deny Rule:**

```yaml
- name: "default-deny"
  description: "Deny all other traffic"
  enabled: true
  priority: 1000   # Low priority (processed last)
  action: "deny"
  direction: "inbound"
  protocol:
    name: "any"
  source_ips:
    - cidr: "0.0.0.0/0"
  destination_zones:
    - name: "dmz"
  log_traffic: true
```

### Protocol Specifications

| Protocol | Name | Number | Description |
|----------|------|--------|-------------|
| TCP | `tcp` | 6 | Transmission Control Protocol |
| UDP | `udp` | 17 | User Datagram Protocol |
| ICMP | `icmp` | 1 | Internet Control Message Protocol |
| Any | `any` | - | Any protocol |

### Rule Priorities

- Lower numbers = Higher priority (processed first)
- Typical ranges:
  - 1-10: Security rules (blocks, denies)
  - 10-50: Management access (SSH, SNMP)
  - 50-100: Application traffic (HTTP, HTTPS)
  - 100-500: Supporting services (DNS, NTP)
  - 900-1000: Default deny rules

### Optional Sections

#### NAT Rules

```yaml
nat_rules:
  - id: "web-dnat"
    name: "web-server-dnat"
    description: "DNAT for web server"
    enabled: true
    type: "destination"     # "source" or "destination"
    original_ip:
      address: "203.0.113.10"  # Public IP
    translated_ip:
      address: "192.168.100.10"  # Internal IP
    protocol:
      name: "tcp"
    original_port:
      number: 80
    translated_port:
      number: 8080
```

#### Global Settings

```yaml
global_settings:
  default_action: "deny"           # Default action for unmatched traffic
  log_denied_traffic: true         # Log all denied traffic
  connection_timeout: 3600         # Connection timeout in seconds
  session_limit: 10000            # Maximum concurrent sessions
  enable_connection_tracking: true # Enable stateful connection tracking
```

---

## Complete Examples

### Simple Web Server Policy

```yaml
metadata:
  name: "simple-web-policy"
  version: "1.0"
  description: "Basic web server policy"
  author: "DevOps Team"

zones:
  local:
    name: "local"
    description: "Local server network"
    networks:
      - cidr: "192.168.0.0/24"

firewall_rules:
  # Allow SSH access
  - name: "allow-ssh"
    description: "Allow SSH access"
    enabled: true
    priority: 10
    action: "allow"
    direction: "inbound"
    protocol:
      name: "tcp"
    source_ips:
      - cidr: "0.0.0.0/0"
    destination_zones:
      - name: "local"
    destination_ports:
      - number: 22
    log_traffic: false

  # Allow HTTP access
  - name: "allow-http"
    description: "Allow HTTP web traffic"
    enabled: true
    priority: 20
    action: "allow"
    direction: "inbound"
    protocol:
      name: "tcp"
    source_ips:
      - cidr: "0.0.0.0/0"
    destination_zones:
      - name: "local"
    destination_ports:
      - number: 80
    log_traffic: false

  # Allow HTTPS access
  - name: "allow-https"
    description: "Allow HTTPS web traffic"
    enabled: true
    priority: 20
    action: "allow"
    direction: "inbound"
    protocol:
      name: "tcp"
    source_ips:
      - cidr: "0.0.0.0/0"
    destination_zones:
      - name: "local"
    destination_ports:
      - number: 443
    log_traffic: false
```

### Comprehensive Enterprise Policy

```yaml
metadata:
  name: "enterprise-security-policy"
  version: "2.1"
  description: "Enterprise network security policy"
  author: "Security Operations Center"
  created_date: "2025-01-15"
  tags: ["enterprise", "production", "security"]

zones:
  dmz:
    name: "dmz"
    description: "Demilitarized zone"
    networks:
      - cidr: "192.168.100.0/24"
  
  internal:
    name: "internal"
    description: "Internal corporate network"
    networks:
      - cidr: "10.0.0.0/8"
      - cidr: "172.16.0.0/12"
  
  management:
    name: "management"
    description: "Network management"
    networks:
      - cidr: "192.168.1.0/24"

firewall_rules:
  # Security rules (high priority)
  - name: "block-known-bad-ips"
    description: "Block known malicious sources"
    enabled: true
    priority: 1
    action: "deny"
    direction: "inbound"
    protocol:
      name: "any"
    source_ips:
      - cidr: "203.0.113.0/24"
    destination_zones:
      - name: "dmz"
    log_traffic: true
    tags: ["security", "blacklist"]

  # Management access
  - name: "allow-ssh-management"
    description: "SSH access from management network"
    enabled: true
    priority: 10
    action: "allow"
    direction: "inbound"
    protocol:
      name: "tcp"
    source_zones:
      - name: "management"
    destination_zones:
      - name: "dmz"
    destination_ports:
      - number: 22
    log_traffic: true
    tags: ["management", "ssh"]

  # Web services
  - name: "allow-web-public"
    description: "Public web access"
    enabled: true
    priority: 20
    action: "allow"
    direction: "inbound"
    protocol:
      name: "tcp"
    source_ips:
      - cidr: "0.0.0.0/0"
    destination_zones:
      - name: "dmz"
    destination_ports:
      - number: 80
      - number: 443
    log_traffic: false
    tags: ["web", "public"]

  # Internal services
  - name: "allow-database-internal"
    description: "Database access to internal network"
    enabled: true
    priority: 30
    action: "allow"
    direction: "outbound"
    protocol:
      name: "tcp"
    source_zones:
      - name: "dmz"
    destination_zones:
      - name: "internal"
    destination_ports:
      - number: 3306  # MySQL
      - number: 5432  # PostgreSQL
    log_traffic: true
    tags: ["database", "internal"]

  # Supporting services
  - name: "allow-dns-outbound"
    description: "Allow DNS queries"
    enabled: true
    priority: 50
    action: "allow"
    direction: "outbound"
    protocol:
      name: "udp"
    source_zones:
      - name: "dmz"
    destination_ports:
      - number: 53
    log_traffic: false
    tags: ["dns", "infrastructure"]

  - name: "allow-ntp-outbound"
    description: "Allow NTP time synchronization"
    enabled: true
    priority: 50
    action: "allow"
    direction: "outbound"
    protocol:
      name: "udp"
    source_zones:
      - name: "dmz"
    destination_ports:
      - number: 123
    log_traffic: false
    tags: ["ntp", "infrastructure"]

  # Default deny
  - name: "default-deny-inbound"
    description: "Default deny all inbound traffic"
    enabled: true
    priority: 1000
    action: "deny"
    direction: "inbound"
    protocol:
      name: "any"
    source_ips:
      - cidr: "0.0.0.0/0"
    destination_zones:
      - name: "dmz"
    log_traffic: true
    tags: ["default", "security"]

global_settings:
  default_action: "deny"
  log_denied_traffic: true
  connection_timeout: 3600
  session_limit: 10000
  enable_connection_tracking: true
```

---

## Best Practices

### Device Configuration

1. **Use SSH Key Authentication**
   - More secure than passwords
   - Use separate keys for different environments
   - Never store passphrases in config files

2. **Organize by Environment**

   ```yaml
   # Group devices logically
   devices:
     # Production servers
     - type: "linux_iptables"
       name: "prod-web-01"
       # ...
     
     # Development servers  
     - type: "linux_iptables"
       name: "dev-web-01"
       # ...
   ```

3. **Use Descriptive Names**
   - Include environment: `prod-web-01`, `dev-db-01`
   - Include function: `web-server`, `database`, `load-balancer`
   - Include location if relevant: `us-east-web-01`

### Policy Configuration

1. **Rule Organization**
   - Use meaningful rule names: `allow-ssh-management` not `rule1`
   - Group related rules with consistent priorities
   - Add descriptions for complex rules

2. **Priority Planning**

   ```yaml
   # 1-10: Security blocks and denies
   # 10-50: Management access
   # 50-100: Application traffic
   # 100-500: Supporting services
   # 900-1000: Default deny
   ```

3. **Use Network Zones**
   - Define logical network segments
   - Simplifies rule management
   - Makes policies more readable

4. **Logging Strategy**
   - Log security events (blocks, management access)
   - Don't log high-volume traffic unless needed
   - Log default deny rules for troubleshooting

5. **Default Deny**
   - Always include explicit default deny rules
   - Place at lowest priority (highest number)
   - Enable logging to catch unexpected traffic

### Security Considerations

1. **Principle of Least Privilege**
   - Only allow necessary traffic
   - Use specific source/destination restrictions
   - Regularly review and remove unused rules

2. **Source Restrictions**

   ```yaml
   # Good: Restrict SSH to management network
   source_zones:
     - name: "management"
   
   # Bad: Allow SSH from anywhere
   source_ips:
     - cidr: "0.0.0.0/0"
   ```

3. **Regular Updates**
   - Review policies quarterly
   - Update blocked IP ranges
   - Remove obsolete rules

---

## Troubleshooting

### Common Device Configuration Issues

**SSH Connection Failures:**

```yaml
# Check these settings:
host: "correct.ip.address"     # Ensure IP/hostname is correct
port: 22                       # Verify SSH port
username: "valid_user"         # User must exist and have sudo access
private_key: "/path/to/key"    # Key file must exist and be readable
```

**Permission Issues:**

```bash
# Fix SSH key permissions
chmod 600 /path/to/private/key

# Ensure user has sudo access on target device
sudo visudo
# Add: username ALL=(ALL) NOPASSWD:ALL
```

### Common Policy Issues

**Rules Not Matching:**

- Check rule priorities (lower numbers first)
- Verify IP ranges and zones are correct
- Ensure protocol specifications match

**Unexpected Compliance Results:**

- Review actual iptables rules with `-v` flag
- Check for extra Docker or system rules
- Verify rule names match between policy and device

### Debugging Commands

```bash
# Test device connectivity
python -c "from audit_agent.cli import main; main()" audit policy.yaml devices.yaml -v

# Validate policy syntax
python -c "from audit_agent.cli import main; main()" validate policy.yaml

# Check actual iptables rules on device
ssh user@device "sudo iptables-save"
```

### Getting Help

- Use `-v` or `-vv` flags for verbose output
- Check the device SSH connectivity manually first
- Validate YAML syntax with online tools
- Review log output for specific error messages

---

## Field Reference

### Device Configuration Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `type` | string | Yes | - | Device type identifier |
| `name` | string | Yes | - | Unique device name |
| `host` | string | Yes | - | IP address or hostname |
| `port` | integer | No | 22 | SSH connection port |
| `username` | string | Yes | - | SSH username |
| `password` | string | No | - | SSH password (not recommended) |
| `private_key` | string | No | - | SSH private key file path |
| `private_key_passphrase` | string | No | - | Passphrase for SSH key (if applicable) |
| `sudo_password` | string | Yes | - | Password for sudo operations |
| `description` | string | No | - | Human-readable description |

### Policy Configuration Fields

#### Metadata

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Policy identifier |
| `version` | string | Yes | Version number |
| `description` | string | No | Policy description |
| `author` | string | No | Policy author |
| `created_date` | string | No | Creation date |
| `tags` | array | No | Organization tags |

#### Firewall Rules

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique rule identifier |
| `description` | string | No | Rule description |
| `enabled` | boolean | Yes | Enable/disable rule |
| `priority` | integer | Yes | Rule processing priority |
| `action` | string | Yes | "allow" or "deny" |
| `direction` | string | Yes | "inbound", "outbound", or "both" |
| `protocol` | object | Yes | Protocol specification |
| `source_ips` | array | No | Source IP ranges |
| `destination_ips` | array | No | Destination IP ranges |
| `source_zones` | array | No | Source network zones |
| `destination_zones` | array | No | Destination network zones |
| `source_ports` | array | No | Source port specifications |
| `destination_ports` | array | No | Destination port specifications |
| `log_traffic` | boolean | No | Enable traffic logging |
| `tags` | array | No | Organization tags |

This completes the comprehensive configuration guide for AuditAgent device and policy files.
