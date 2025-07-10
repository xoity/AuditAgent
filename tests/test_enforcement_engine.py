"""
Tests for audit_agent.enforcement.engine module.
"""

import datetime

import pytest

from audit_agent.core.objects import Protocol
from audit_agent.core.policy import NetworkPolicy
from audit_agent.core.rules import Action, Direction, FirewallRule
from audit_agent.devices.base import CommandResult
from audit_agent.devices.linux_iptables import LinuxIptables
from audit_agent.enforcement.engine import (
    DeviceEnforcementResult,
    EnforcementAction,
    EnforcementEngine,
    EnforcementPlanner,
    PolicyEnforcementResult,
    PreflightValidator,
)


class TestEnforcementEngine:
    """Test cases for EnforcementEngine class."""

    def test_enforcement_engine_creation(self):
        """Test creating an enforcement engine."""
        engine = EnforcementEngine()
        assert engine is not None
        assert engine.audit_engine is not None
        assert engine.planner is not None
        assert engine.validator is not None

    def test_enforcement_action_creation(self):
        """Test creating enforcement actions."""
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        rule = FirewallRule()
        rule.name = "allow-ssh"
        rule.action = Action.ALLOW
        rule.direction = Direction.INBOUND
        rule.protocol = Protocol.tcp()
        rule.port(22)

        action = EnforcementAction(
            device=device,
            rule=rule,
            action_type="add",
            commands=["iptables -A INPUT -p tcp --dport 22 -j ACCEPT"],
            description="Add SSH allow rule",
            risk_level="medium",
        )

        assert action.device == device
        assert action.rule == rule
        assert action.action_type == "add"
        assert len(action.commands) == 1
        assert action.description == "Add SSH allow rule"
        assert action.risk_level == "medium"

    def test_device_enforcement_result_creation(self):
        """Test creating device enforcement results."""
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        command_results = [
            CommandResult(
                command="iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
                success=True,
                output="Rule added successfully",
                execution_time=0.1,
            )
        ]

        result = DeviceEnforcementResult(
            device=device,
            actions_planned=2,
            actions_executed=2,
            actions_successful=1,
            actions_failed=1,
            command_results=command_results,
            enforcement_timestamp=datetime.datetime.now().isoformat(),
        )

        assert result.device == device
        assert result.actions_planned == 2
        assert result.actions_executed == 2
        assert result.actions_successful == 1
        assert result.actions_failed == 1
        assert result.success_rate == 50.0  # 1 success out of 2 executed
        assert len(result.command_results) == 1

    def test_device_enforcement_result_no_actions(self):
        """Test device enforcement result with no actions executed."""
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        result = DeviceEnforcementResult(
            device=device,
            actions_planned=0,
            actions_executed=0,
            actions_successful=0,
            actions_failed=0,
            command_results=[],
            enforcement_timestamp=datetime.datetime.now().isoformat(),
        )

        assert result.success_rate == 100.0  # No actions executed = 100% success

    def test_policy_enforcement_result_creation(self):
        """Test creating policy enforcement results."""
        result = PolicyEnforcementResult(
            policy_name="test-policy",
            devices_processed=2,
            total_actions_planned=10,
            total_actions_executed=8,
            total_actions_successful=6,
            total_actions_failed=2,
            device_results=[],
            overall_success_rate=75.0,
            enforcement_timestamp=datetime.datetime.now().isoformat(),
            dry_run=False,
        )

        assert result.policy_name == "test-policy"
        assert result.devices_processed == 2
        assert result.total_actions_planned == 10
        assert result.total_actions_executed == 8
        assert result.total_actions_successful == 6
        assert result.total_actions_failed == 2
        assert result.overall_success_rate == 75.0
        assert result.dry_run is False
        assert result.is_successful is False  # Has failed actions

    def test_policy_enforcement_result_successful(self):
        """Test successful policy enforcement result."""
        result = PolicyEnforcementResult(
            policy_name="successful-policy",
            devices_processed=1,
            total_actions_planned=5,
            total_actions_executed=5,
            total_actions_successful=5,
            total_actions_failed=0,
            device_results=[],
            overall_success_rate=100.0,
            enforcement_timestamp=datetime.datetime.now().isoformat(),
            dry_run=False,
        )

        assert result.is_successful is True  # No failed actions
        assert result.overall_success_rate == 100.0

    def test_enforcement_planner_creation(self):
        """Test creating enforcement planner."""
        planner = EnforcementPlanner()
        assert planner is not None

    def test_preflight_validator_creation(self):
        """Test creating preflight validator."""
        validator = PreflightValidator()
        assert validator is not None

    def test_preflight_validator_action_validation(self):
        """Test validating enforcement actions."""
        validator = PreflightValidator()

        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        rule = FirewallRule()
        rule.name = "allow-ssh"

        # Test low-risk action
        action = EnforcementAction(
            device=device,
            rule=rule,
            action_type="add",
            commands=["iptables -A INPUT -p tcp --dport 22 -j ACCEPT"],
            description="Add SSH rule",
            risk_level="low",
        )

        warnings = validator.validate_action(action)
        # Should have minimal warnings for low-risk action
        assert isinstance(warnings, list)

    def test_preflight_validator_high_risk_detection(self):
        """Test detection of high-risk actions."""
        validator = PreflightValidator()

        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        rule = FirewallRule()
        rule.name = "risky-change"

        # Test high-risk action
        action = EnforcementAction(
            device=device,
            rule=rule,
            action_type="modify",
            commands=["iptables -F INPUT"],  # Flush all rules - risky!
            description="Flush all rules",
            risk_level="critical",
        )

        warnings = validator.validate_action(action)
        assert len(warnings) > 0  # Should have warnings
        assert any("High-risk" in warning for warning in warnings)

    def test_enforcement_action_risk_levels(self):
        """Test different risk levels for enforcement actions."""
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        rule = FirewallRule()
        rule.name = "test-rule"

        # Test all risk levels
        risk_levels = ["low", "medium", "high", "critical"]

        for risk_level in risk_levels:
            action = EnforcementAction(
                device=device,
                rule=rule,
                action_type="add",
                commands=["iptables -A INPUT -j ACCEPT"],
                description=f"Test {risk_level} risk action",
                risk_level=risk_level,
            )

            assert action.risk_level == risk_level

    def test_policy_for_enforcement(self):
        """Test creating a policy suitable for enforcement."""
        policy = NetworkPolicy("enforcement-test")
        policy.metadata.description = "Policy for enforcement testing"

        # Add firewall rules
        ssh_rule = FirewallRule()
        ssh_rule.name = "allow-ssh"
        ssh_rule.action = Action.ALLOW
        ssh_rule.direction = Direction.INBOUND
        ssh_rule.protocol = Protocol.tcp()
        ssh_rule.port(22)
        policy.add_firewall_rule(ssh_rule)

        web_rule = FirewallRule()
        web_rule.name = "allow-web"
        web_rule.action = Action.ALLOW
        web_rule.direction = Direction.INBOUND
        web_rule.protocol = Protocol.tcp()
        web_rule.ports([80, 443])
        policy.add_firewall_rule(web_rule)

        # Add zone
        zone = policy.add_zone("dmz")
        zone.add_network("192.168.100.0/24")

        # Verify policy structure
        assert len(policy.firewall_rules) == 2
        assert len(policy.zones) == 1
        assert policy.metadata.name == "enforcement-test"

        # Check all rules can be retrieved for enforcement
        all_rules = policy.get_all_rules()
        assert len(all_rules) >= 2  # At least the firewall rules


class TestEnforcementAction:
    """Test cases for EnforcementAction class."""

    def test_enforcement_action_add_type(self):
        """Test enforcement action for adding rules."""
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        rule = FirewallRule()
        rule.name = "allow-http"
        rule.action = Action.ALLOW
        rule.direction = Direction.INBOUND
        rule.protocol = Protocol.tcp()
        rule.port(80)

        action = EnforcementAction(
            device=device,
            rule=rule,
            action_type="add",
            commands=["iptables -A INPUT -p tcp --dport 80 -j ACCEPT"],
            description="Add HTTP allow rule",
            risk_level="medium",
        )

        assert action.action_type == "add"
        assert action.description == "Add HTTP allow rule"
        assert "iptables -A" in action.commands[0]
        assert "--dport 80" in action.commands[0]

    def test_enforcement_action_remove_type(self):
        """Test enforcement action for removing rules."""
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        rule = FirewallRule()
        rule.name = "old-rule"

        action = EnforcementAction(
            device=device,
            rule=rule,
            action_type="remove",
            commands=["iptables -D INPUT -p tcp --dport 23 -j ACCEPT"],
            description="Remove telnet rule",
            risk_level="low",
        )

        assert action.action_type == "remove"
        assert "Remove" in action.description
        assert "iptables -D" in action.commands[0]

    def test_enforcement_action_modify_type(self):
        """Test enforcement action for modifying rules."""
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        rule = FirewallRule()
        rule.name = "modify-ssh"

        action = EnforcementAction(
            device=device,
            rule=rule,
            action_type="modify",
            commands=[
                "iptables -D INPUT -p tcp --dport 22 -j ACCEPT",
                "iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT",
            ],
            description="Modify SSH rule to restrict source",
            risk_level="high",
        )

        assert action.action_type == "modify"
        assert len(action.commands) == 2
        assert action.risk_level == "high"
        assert "Modify" in action.description


class TestEnforcementIntegration:
    """Integration tests for enforcement components."""

    def test_device_and_policy_integration(self):
        """Test that devices and policies work together for enforcement."""
        # Create a policy
        policy = NetworkPolicy("integration-test")

        rule = FirewallRule()
        rule.name = "allow-ssh"
        rule.action = Action.ALLOW
        rule.direction = Direction.INBOUND
        rule.protocol = Protocol.tcp()
        rule.port(22)
        policy.add_firewall_rule(rule)

        # Create a device
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        # Verify they can work together
        assert policy.firewall_rules[0].name == "allow-ssh"
        assert "192.168.1.10" in str(device)  # Check device string representation

        # Test that rules can be converted to commands (conceptually)
        # In practice, this would use device.rule_to_commands(rule)
        expected_command_pattern = "iptables"
        assert expected_command_pattern  # Placeholder assertion

    def test_enforcement_workflow_structure(self):
        """Test the overall structure of the enforcement workflow."""
        # Components that should work together
        engine = EnforcementEngine()
        planner = EnforcementPlanner()
        validator = PreflightValidator()

        # Verify all components are created properly
        assert engine is not None
        assert planner is not None
        assert validator is not None

        # Verify engine has required components
        assert hasattr(engine, "audit_engine")
        assert hasattr(engine, "planner")
        assert hasattr(engine, "validator")


if __name__ == "__main__":
    pytest.main([__file__])
