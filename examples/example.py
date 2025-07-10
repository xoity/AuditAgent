#!/usr/bin/env python3
"""
Example script demonstrating the AuditAgent framework.

This script shows how to:
1. Define a network security policy programmatically
2. Connect to network devices
3. Audit the current configuration
4. Enforce policy changes
"""

import asyncio
from audit_agent import NetworkPolicy, FirewallRule


async def main():
    """Main example function."""

    print("🔒 AuditAgent Example - Network Security Policy Automation")
    print("=" * 60)

    # 1. Create a network security policy
    print("\n📋 Creating network security policy...")

    policy = create_example_policy()
    print(f"✓ Created policy: {policy.metadata.name}")
    print(f"  - Zones: {len(policy.zones)}")
    print(f"  - Firewall rules: {len(policy.firewall_rules)}")

    # 2. Validate the policy
    print("\n🔍 Validating policy...")
    validation_result = policy.validate_policy()

    if validation_result.is_valid:
        print("✓ Policy is valid")
    else:
        print("❌ Policy validation failed:")
        for error in validation_result.errors:
            print(f"  - {error}")
        for warning in validation_result.warnings:
            print(f"  ⚠️  {warning}")

    # 3. Define target devices (mock for this example)
    print("\n🖥️  Defining target devices...")
    devices = create_example_devices()
    print(f"✓ Defined {len(devices)} devices")

    # 4. Run audit (in a real scenario, this would connect to actual devices)
    print("\n🔍 Running policy audit...")

    try:
        # In this example, we'll simulate the audit since we don't have real devices
        print("  (This would normally connect to real devices)")
        print("  Simulating audit results...")

        # For demonstration, let's show what a real audit would look like
        print_audit_example()

    except Exception as e:
        print(f"❌ Audit failed: {e}")

    # 5. Show enforcement example
    print("\n⚙️  Enforcement example...")

    print("  (In dry-run mode, this would show what changes would be made)")
    print_enforcement_example()

    # 6. Export policy to file
    print("\n💾 Exporting policy...")
    yaml_content = policy.export_to_yaml()

    with open("example_policy.yaml", "w") as f:
        f.write(yaml_content)
    print("✓ Policy exported to example_policy.yaml")

    print("\n🎉 Example completed successfully!")
    print("\nNext steps:")
    print("  1. Edit the device credentials in devices.yaml")
    print("  2. Run: audit-agent audit example_policy.yaml devices.yaml")
    print("  3. Review the audit results")
    print("  4. Run: audit-agent enforce example_policy.yaml devices.yaml --dry-run")


def create_example_policy() -> NetworkPolicy:
    """Create an example network security policy."""

    # Create policy
    policy = NetworkPolicy("production-web-servers")
    policy.metadata.description = "Security policy for production web servers"
    policy.metadata.author = "Security Team"

    # Define zones
    dmz_zone = policy.add_zone("dmz")
    dmz_zone.add_network("192.168.100.0/24")
    dmz_zone.description = "DMZ for web servers"

    mgmt_zone = policy.add_zone("management")
    mgmt_zone.add_network("10.0.0.0/24")
    mgmt_zone.description = "Management network"

    internal_zone = policy.add_zone("internal")
    internal_zone.add_network("172.16.0.0/16")
    internal_zone.description = "Internal corporate network"

    # SSH access from management only
    ssh_rule = (
        FirewallRule()
        .allow_inbound()
        .tcp()
        .port(22)
        .from_zone("management")
        .to_zone("dmz")
        .log()
        .priority_high()
    )
    ssh_rule.name = "allow-ssh-management"
    ssh_rule.description = "SSH access from management network only"
    ssh_rule.add_tag("management")
    ssh_rule.add_tag("ssh")
    policy.add_firewall_rule(ssh_rule)

    # Web traffic from internet
    http_rule = FirewallRule().allow_inbound().tcp().port(80).from_any().to_zone("dmz")
    http_rule.name = "allow-http-public"
    http_rule.description = "HTTP traffic from internet"
    http_rule.add_tag("web")
    policy.add_firewall_rule(http_rule)

    https_rule = (
        FirewallRule().allow_inbound().tcp().port(443).from_any().to_zone("dmz")
    )
    https_rule.name = "allow-https-public"
    https_rule.description = "HTTPS traffic from internet"
    https_rule.add_tag("web")
    policy.add_firewall_rule(https_rule)

    # Database access to internal network
    db_rule = (
        FirewallRule()
        .allow_outbound()
        .tcp()
        .ports([3306, 5432])
        .from_zone("dmz")
        .to_zone("internal")
        .log()
    )
    db_rule.name = "allow-database-access"
    db_rule.description = "Database access from DMZ to internal"
    db_rule.add_tag("database")
    policy.add_firewall_rule(db_rule)

    # Block malicious IPs
    malicious_rule = (
        FirewallRule()
        .deny_inbound()
        .any_protocol()
        .from_ip("192.0.2.0/24")  # Example malicious range
        .to_zone("dmz")
        .log()
        .priority_high()
    )
    malicious_rule.name = "block-malicious-ips"
    malicious_rule.description = "Block known malicious IP ranges"
    malicious_rule.add_tag("security")
    malicious_rule.add_tag("blacklist")
    policy.add_firewall_rule(malicious_rule)

    # Default deny
    deny_rule = (
        FirewallRule()
        .deny_inbound()
        .any_protocol()
        .from_any()
        .to_zone("dmz")
        .log()
        .priority_low()
    )
    deny_rule.name = "default-deny"
    deny_rule.description = "Default deny rule"
    deny_rule.add_tag("default")
    policy.add_firewall_rule(deny_rule)

    return policy


def create_example_devices():
    """Create example device configurations."""

    devices = [
        {
            "type": "cisco_asa",
            "name": "dmz-firewall-01",
            "host": "192.168.1.10",
            "username": "admin",
            "password": "your_password",
            "description": "Primary DMZ firewall",
        },
        {
            "type": "cisco_asa",
            "name": "dmz-firewall-02",
            "host": "192.168.1.11",
            "username": "admin",
            "password": "your_password",
            "description": "Secondary DMZ firewall",
        },
    ]

    return devices


def print_audit_example():
    """Print example audit output."""

    print("  📊 Audit Results:")
    print("    Overall Compliance: 85%")
    print("    Devices Audited: 2")
    print("    Issues Found: 3")
    print("")
    print("    🔍 Issues:")
    print("      ❌ dmz-firewall-01: Missing SSH rule from management")
    print("      ⚠️  dmz-firewall-01: Extra rule allowing Telnet access")
    print("      ⚠️  dmz-firewall-02: Missing logging on deny rules")


def print_enforcement_example():
    """Print example enforcement output."""

    print("  🔧 Planned Changes:")
    print("    Device: dmz-firewall-01")
    print(
        "      ➕ Add: access-list POLICY_ACL extended permit tcp 10.0.0.0 255.255.255.0 192.168.100.0 255.255.255.0 eq 22 log"
    )
    print("      ➖ Remove: access-list OLD_ACL extended permit tcp any any eq 23")
    print("")
    print("    Device: dmz-firewall-02")
    print(
        "      🔧 Modify: access-list POLICY_ACL extended deny ip any any log (add logging)"
    )


if __name__ == "__main__":
    asyncio.run(main())
