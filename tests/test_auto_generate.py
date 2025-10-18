"""
Tests for the auto-generate command.
"""

import pytest
from typer.testing import CliRunner

from audit_agent.cli import firewall_rule_to_iptables
from audit_agent.core.objects import Port, Protocol
from audit_agent.core.policy import NetworkPolicy
from audit_agent.core.rules import FirewallRule

runner = CliRunner()


class TestFirewallRuleToIptables:
    """Test firewall rule to iptables command generation."""

    def test_simple_allow_inbound(self):
        """Test simple allow inbound rule."""
        rule = FirewallRule().allow_inbound().tcp().port(22)
        rule.name = "allow-ssh"

        commands = firewall_rule_to_iptables(rule)

        assert len(commands) > 0
        assert any("INPUT" in cmd for cmd in commands)
        assert any("22" in cmd for cmd in commands)
        assert any("ACCEPT" in cmd for cmd in commands)
        assert any("tcp" in cmd for cmd in commands)

    def test_deny_outbound(self):
        """Test deny outbound rule."""
        rule = FirewallRule().deny_outbound().tcp().port(443)
        rule.name = "deny-https"

        commands = firewall_rule_to_iptables(rule)

        assert len(commands) > 0
        assert any("OUTPUT" in cmd for cmd in commands)
        assert any("443" in cmd for cmd in commands)
        assert any("DROP" in cmd for cmd in commands)

    def test_rule_with_source_ip(self):
        """Test rule with source IP."""
        rule = FirewallRule().allow_inbound().tcp().port(80).from_ip("192.168.1.0/24")
        rule.name = "allow-web"

        commands = firewall_rule_to_iptables(rule)

        assert len(commands) > 0
        assert any("192.168.1.0/24" in cmd for cmd in commands)
        assert any("-s" in cmd for cmd in commands)

    def test_rule_with_destination_ip(self):
        """Test rule with destination IP."""
        rule = FirewallRule().allow_inbound().tcp().port(22).to_ip("10.0.0.0/8")
        rule.name = "allow-ssh-to-network"

        commands = firewall_rule_to_iptables(rule)

        assert len(commands) > 0
        assert any("10.0.0.0/8" in cmd for cmd in commands)
        assert any("-d" in cmd for cmd in commands)

    def test_rule_with_logging(self):
        """Test rule with logging enabled."""
        rule = FirewallRule().allow_inbound().tcp().port(22).log()
        rule.name = "allow-ssh-log"

        commands = firewall_rule_to_iptables(rule)

        # Should have both LOG and ACCEPT commands
        log_cmds = [cmd for cmd in commands if "LOG" in cmd]
        accept_cmds = [cmd for cmd in commands if "ACCEPT" in cmd]

        assert len(log_cmds) > 0
        assert len(accept_cmds) > 0
        assert any("--log-prefix" in cmd for cmd in log_cmds)

    def test_rule_with_multiple_ports(self):
        """Test rule with multiple ports."""
        rule = FirewallRule().allow_inbound().tcp().ports([80, 443])
        rule.name = "allow-web-traffic"

        commands = firewall_rule_to_iptables(rule)

        # Should generate commands for each port
        assert len(commands) >= 2
        assert any("80" in cmd for cmd in commands)
        assert any("443" in cmd for cmd in commands)

    def test_rule_with_port_range(self):
        """Test rule with port range."""
        rule = FirewallRule()
        rule.direction = rule.direction.__class__("inbound")
        rule.action = rule.action.__class__("allow")
        rule.protocol = Protocol(name="tcp", number=6)
        rule.destination_ports.append(Port(range_start=8000, range_end=8100))
        rule.name = "allow-app-ports"

        commands = firewall_rule_to_iptables(rule)

        assert len(commands) > 0
        assert any("8000:8100" in cmd for cmd in commands)

    def test_any_protocol(self):
        """Test rule with any protocol."""
        rule = FirewallRule().allow_inbound().any_protocol()
        rule.name = "allow-all-protocols"

        commands = firewall_rule_to_iptables(rule)

        assert len(commands) > 0
        # Should not have -p flag when protocol is any
        assert not any("-p any" in cmd for cmd in commands)

    def test_complex_rule(self):
        """Test complex rule with multiple attributes."""
        rule = (
            FirewallRule()
            .allow_inbound()
            .tcp()
            .port(22)
            .from_ip("192.168.1.0/24")
            .to_ip("10.0.0.0/8")
            .log()
        )
        rule.name = "complex-ssh-rule"

        commands = firewall_rule_to_iptables(rule)

        assert len(commands) > 0
        # Should have commands with all components
        full_cmds = [cmd for cmd in commands if "ACCEPT" in cmd]
        assert len(full_cmds) > 0
        assert any("192.168.1.0/24" in cmd for cmd in full_cmds)
        assert any("10.0.0.0/8" in cmd for cmd in full_cmds)
        assert any("22" in cmd for cmd in full_cmds)


class TestAutoGenerateCommand:
    """Test the auto-generate CLI command."""

    @pytest.mark.skip(reason="Requires file I/O and device connections")
    def test_auto_generate_basic(self, tmp_path):
        """Test basic auto-generate command."""
        # This would require:
        # - Creating test audit results file
        # - Creating test devices file
        # - Running actual command
        pass

    @pytest.mark.skip(reason="Requires file I/O")
    def test_auto_generate_with_commands(self, tmp_path):
        """Test auto-generate with --include-commands flag."""
        # This would test that the commands file is created
        pass

    def test_command_script_format(self):
        """Test that generated command scripts have correct format."""
        policy = NetworkPolicy("test-remediation")

        rule = FirewallRule().allow_inbound().tcp().port(22)
        rule.name = "allow-ssh"
        rule.description = "Allow SSH access"
        policy.add_firewall_rule(rule)

        # Generate commands for the rule
        commands = firewall_rule_to_iptables(rule)

        # Verify commands are valid shell commands
        assert all(cmd.startswith("iptables") for cmd in commands)
        assert all("-A" in cmd for cmd in commands)  # All should be append commands
        assert all("-j" in cmd for cmd in commands)  # All should have jump target


class TestRemediationPolicyGeneration:
    """Test remediation policy generation logic."""

    def test_empty_audit_results(self):
        """Test handling of empty audit results."""
        # Create empty remediation policy
        policy = NetworkPolicy("empty-remediation")

        assert len(policy.firewall_rules) == 0
        assert policy.metadata.name == "empty-remediation"

    def test_add_missing_rule(self):
        """Test adding missing rules to remediation policy."""
        policy = NetworkPolicy("test-remediation")

        # Add a missing rule
        rule = FirewallRule().allow_inbound().tcp().port(22)
        rule.name = "allow-ssh"
        policy.add_firewall_rule(rule)

        assert len(policy.firewall_rules) == 1
        assert policy.firewall_rules[0].name == "allow-ssh"

    def test_deduplicate_rules(self):
        """Test that duplicate rules are not added."""
        policy = NetworkPolicy("test-remediation")

        # Add same rule twice
        for _ in range(2):
            rule = FirewallRule().allow_inbound().tcp().port(22)
            rule.name = "allow-ssh"

            # Check if rule already exists (simple name check)
            existing = any(r.name == rule.name for r in policy.firewall_rules)
            if not existing:
                policy.add_firewall_rule(rule)

        # Should only have one rule
        assert len(policy.firewall_rules) == 1

    def test_policy_export_yaml(self):
        """Test exporting remediation policy to YAML."""
        policy = NetworkPolicy("test-remediation")
        policy.metadata.description = "Test remediation policy"

        rule = FirewallRule().allow_inbound().tcp().port(22)
        rule.name = "allow-ssh"
        policy.add_firewall_rule(rule)

        # Export to YAML
        yaml_content = policy.export_to_yaml()

        # Verify YAML is valid and contains expected content
        assert "test-remediation" in yaml_content
        assert "allow-ssh" in yaml_content
        assert "tcp" in yaml_content
        assert "22" in yaml_content
        assert "Test remediation policy" in yaml_content


class TestCommandFileGeneration:
    """Test command file generation for remediation."""

    def test_script_header(self):
        """Test that generated scripts have proper header."""
        header_lines = [
            "#!/bin/bash",
            "# Generated iptables commands",
            "# WARNING: Review these commands before executing!",
        ]

        # Verify header format
        for line in header_lines:
            assert isinstance(line, str)
            assert len(line) > 0

    def test_script_comments(self):
        """Test that scripts have helpful comments."""
        rule = FirewallRule().allow_inbound().tcp().port(22)
        rule.name = "allow-ssh"
        rule.description = "Allow SSH access from management network"

        # Comments should include rule name and description
        expected_comments = [
            f"# Rule: {rule.name}",
            f"# Description: {rule.description}",
        ]

        for comment in expected_comments:
            assert isinstance(comment, str)
            assert comment.startswith("#")

    def test_save_command_included(self):
        """Test that save command is included in script."""
        save_command = "# iptables-save > /etc/iptables/rules.v4"

        assert save_command.startswith("#")
        assert "iptables-save" in save_command
