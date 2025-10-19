#!/usr/bin/env python3
"""
Example script demonstrating the AuditAgent framework for Linux iptables.

This script shows how to:
1. Create a network security policy
2. Define Linux servers with iptables
3. Audit the current state
4. Enforce policy changes

Usage:
    python linux_example.py
"""

import asyncio

from audit_agent import FirewallRule, LinuxIptables, NetworkPolicy


async def main():
    print("🔥 AuditAgent - Linux iptables Example")
    print("=" * 50)

    # 1. Create a network security policy
    print("\n📋 Creating network security policy...")

    policy = NetworkPolicy("linux-web-server-policy")
    policy.metadata.description = "Security policy for Linux web servers"
    policy.metadata.author = "DevOps Team"

    # Add network zones
    dmz_zone = policy.add_zone("dmz")
    dmz_zone.add_network("192.168.100.0/24")
    dmz_zone.description = "DMZ zone for web servers"

    mgmt_zone = policy.add_zone("management")
    mgmt_zone.add_network("10.0.0.0/24")
    mgmt_zone.description = "Management network"

    # 2. Define firewall rules using the fluent interface
    print("\n🛡️  Adding firewall rules...")

    # Allow SSH from management network
    ssh_rule = (
        FirewallRule()
        .allow_inbound()
        .tcp()
        .port(22)
        .from_ip("10.0.0.0/24")
        .to_zone("dmz")
        .log()
        .priority_high()
    )
    ssh_rule.name = "allow-ssh-management"
    ssh_rule.description = "SSH access from management network"
    policy.add_firewall_rule(ssh_rule)

    # Allow HTTP and HTTPS from anywhere
    web_rule = (
        FirewallRule()
        .allow_inbound()
        .tcp()
        .ports([80, 443])
        .from_any()
        .to_zone("dmz")
        .log()
    )
    web_rule.name = "allow-web-traffic"
    web_rule.description = "HTTP/HTTPS traffic to web servers"
    policy.add_firewall_rule(web_rule)

    # Allow database connections from DMZ to database servers
    db_rule = (
        FirewallRule()
        .allow_outbound()
        .tcp()
        .ports([3306, 5432])  # MySQL and PostgreSQL
        .from_zone("dmz")
        .to_ip("192.168.200.0/24")  # Database subnet
        .log()
    )
    db_rule.name = "allow-database-access"
    db_rule.description = "Database access from web servers"
    policy.add_firewall_rule(db_rule)

    # Drop all other inbound traffic
    deny_rule = (
        FirewallRule()
        .deny_inbound()
        .any_protocol()
        .from_any()
        .to_zone("dmz")
        .log()
        .priority_low()
    )
    deny_rule.name = "deny-all-other"
    deny_rule.description = "Deny all other inbound traffic"
    policy.add_firewall_rule(deny_rule)

    print(f"✓ Policy created with {len(policy.firewall_rules)} firewall rules")

    # 3. Validate the policy
    print("\n🔍 Validating policy...")
    validation = policy.validate_policy()

    if validation.is_valid:
        print("✓ Policy validation passed")
    else:
        print("❌ Policy validation failed:")
        for error in validation.errors:
            print(f"  - {error}")
        for warning in validation.warnings:
            print(f"  ⚠️  {warning}")

    # 4. Define Linux servers (these would be real servers in production)
    print("\n🖥️  Defining Linux servers...")

    # Note: These are example servers - in real usage, you'd provide actual credentials
    servers = [
        LinuxIptables(
            host="192.168.100.10",
            username="admin",
            password="your_password",  # In production, use SSH keys
            sudo_password="sudo_password",
            port=22,
        ),
        LinuxIptables(
            host="192.168.100.11",
            username="admin",
            private_key="/path/to/private/key",  # SSH key authentication
            sudo_password=None,  # Passwordless sudo
        ),
    ]

    print(f"✓ Defined {len(servers)} Linux servers")

    # 5. Export policy to file
    print("\n💾 Exporting policy...")

    yaml_content = policy.export_to_yaml()
    with open("linux-web-policy.yaml", "w") as f:
        f.write(yaml_content)
    print("✓ Policy exported to linux-web-policy.yaml")

    json_content = policy.export_to_json()
    with open("linux-web-policy.json", "w") as f:
        f.write(json_content)
    print("✓ Policy exported to linux-web-policy.json")

    # 6. Demonstrate audit (would require actual server connections)
    print("\n🔍 Audit Example (dry-run)...")

    try:
        # audit_engine = AuditEngine()
        # Note: This would fail without actual server connections
        # audit_result = await audit_engine.audit_policy(policy, servers)
        # print(f"Overall compliance: {audit_result.overall_compliance_percentage:.1f}%")
        print("ℹ️  Audit requires actual server connections")
        print("   In production, this would:")
        print("   - Connect to each Linux server via SSH")
        print("   - Retrieve current iptables rules using 'iptables-save'")
        print("   - Compare against the defined policy")
        print("   - Generate compliance report")

    except Exception as e:
        print(f"ℹ️  Audit simulation: {e}")

    # 7. Demonstrate enforcement (would require actual server connections)
    print("\n⚡ Enforcement Example (dry-run)...")

    try:
        # enforcement_engine = EnforcementEngine()
        # Note: This would fail without actual server connections
        # enforcement_result = await enforcement_engine.enforce_policy(policy, servers, dry_run=True)
        # print(f"Planned actions: {enforcement_result.total_actions_planned}")
        print("ℹ️  Enforcement requires actual server connections")
        print("   In production, this would:")
        print("   - Generate iptables commands for each rule")
        print("   - Execute commands via SSH with sudo")
        print("   - Support dry-run mode for safety")
        print("   - Provide detailed execution results")

    except Exception as e:
        print(f"ℹ️  Enforcement simulation: {e}")

    # 8. Show example iptables commands that would be generated
    print("\n🔧 Example iptables commands that would be generated:")
    print("-" * 60)

    for rule in policy.firewall_rules:
        # This would use the actual device implementation
        print(f"\n# Rule: {rule.name}")
        print(f"# Description: {rule.description}")

        # Simulate command generation (simplified)
        if rule.name == "allow-ssh-management":
            print(
                "iptables -A INPUT -p tcp -s 10.0.0.0/24 --dport 22 -j LOG --log-prefix '[allow-ssh-management] '"
            )
            print("iptables -A INPUT -p tcp -s 10.0.0.0/24 --dport 22 -j ACCEPT")
        elif rule.name == "allow-web-traffic":
            print(
                "iptables -A INPUT -p tcp --dport 80 -j LOG --log-prefix '[allow-web-traffic] '"
            )
            print("iptables -A INPUT -p tcp --dport 80 -j ACCEPT")
            print(
                "iptables -A INPUT -p tcp --dport 443 -j LOG --log-prefix '[allow-web-traffic] '"
            )
            print("iptables -A INPUT -p tcp --dport 443 -j ACCEPT")
        elif rule.name == "allow-database-access":
            print(
                "iptables -A OUTPUT -p tcp -d 192.168.200.0/24 --dport 3306 -j LOG --log-prefix '[allow-database-access] '"
            )
            print(
                "iptables -A OUTPUT -p tcp -d 192.168.200.0/24 --dport 3306 -j ACCEPT"
            )
            print(
                "iptables -A OUTPUT -p tcp -d 192.168.200.0/24 --dport 5432 -j LOG --log-prefix '[allow-database-access] '"
            )
            print(
                "iptables -A OUTPUT -p tcp -d 192.168.200.0/24 --dport 5432 -j ACCEPT"
            )
        elif rule.name == "deny-all-other":
            print("iptables -A INPUT -j LOG --log-prefix '[deny-all-other] '")
            print("iptables -A INPUT -j DROP")

    print("\n" + "=" * 50)
    print("🎉 Example completed successfully!")
    print("\nNext steps:")
    print("1. Update server credentials in the script")
    print("2. Ensure SSH key-based authentication is set up")
    print("3. Test with --dry-run mode first")
    print("4. Use the CLI: audit-agent audit linux-web-policy.yaml devices.yaml")


if __name__ == "__main__":
    asyncio.run(main())
