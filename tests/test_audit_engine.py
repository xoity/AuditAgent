"""
Tests for audit_agent.audit.engine module.
"""

import pytest

from audit_agent.audit.engine import AuditEngine, ComplianceIssue, DeviceAuditResult
from audit_agent.core.objects import Protocol
from audit_agent.core.policy import NetworkPolicy
from audit_agent.core.rules import Action, Direction, FirewallRule
from audit_agent.devices.linux_iptables import LinuxIptables


class TestAuditEngine:
    """Test cases for AuditEngine class."""

    def test_audit_engine_creation(self):
        """Test creating an audit engine."""
        engine = AuditEngine()
        assert engine is not None

    def test_compliance_issue_creation(self):
        """Test creating a compliance issue."""
        issue = ComplianceIssue(
            severity="high",
            rule_id="rule-001",
            rule_name="allow-ssh",
            issue_type="missing_rule",
            description="SSH rule is missing",
            device="192.168.1.10",
            recommendation="Add SSH allow rule",
        )

        assert issue.severity == "high"
        assert issue.rule_id == "rule-001"
        assert issue.rule_name == "allow-ssh"
        assert issue.issue_type == "missing_rule"
        assert issue.description == "SSH rule is missing"
        assert issue.device == "192.168.1.10"
        assert issue.recommendation == "Add SSH allow rule"

    def test_device_audit_result_creation(self):
        """Test creating device audit results."""
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        issues = [
            ComplianceIssue(
                severity="medium",
                rule_id="rule-001",
                rule_name="allow-http",
                issue_type="misconfigured_rule",
                description="HTTP rule port mismatch",
                device="192.168.1.10",
                recommendation="Update port to 80",
            )
        ]

        result = DeviceAuditResult(
            device=device,
            total_rules_checked=10,
            compliant_rules=8,
            non_compliant_rules=2,
            issues=issues,
            compliance_percentage=80.0,
            audit_timestamp="2024-01-01T12:00:00Z",
        )

        assert result.device == device
        assert result.total_rules_checked == 10
        assert result.compliant_rules == 8
        assert result.non_compliant_rules == 2
        assert len(result.issues) == 1
        assert result.compliance_percentage == 80.0
        assert result.is_compliant is False  # has non-compliant rules

    def test_device_audit_result_compliant(self):
        """Test compliant device audit result."""
        device = LinuxIptables(host="192.168.1.10", username="admin", password="secret")

        result = DeviceAuditResult(
            device=device,
            total_rules_checked=5,
            compliant_rules=5,
            non_compliant_rules=0,
            issues=[],
            compliance_percentage=100.0,
            audit_timestamp="2024-01-01T12:00:00Z",
        )

        assert result.is_compliant is True  # no non-compliant rules
        assert len(result.issues) == 0
        assert result.compliance_percentage == 100.0

    def test_firewall_rule_creation_for_audit(self):
        """Test creating firewall rules that would be audited."""
        rule = FirewallRule()
        rule.name = "allow-ssh"
        rule.action = Action.ALLOW
        rule.direction = Direction.INBOUND
        rule.protocol = Protocol.tcp()
        rule.port(22)
        rule.from_ip("192.168.1.0/24")

        # Test rule properties
        assert rule.name == "allow-ssh"
        assert rule.action == Action.ALLOW
        assert rule.direction == Direction.INBOUND
        assert rule.protocol.name == "tcp"
        assert len(rule.destination_ports) == 1
        assert rule.destination_ports[0].number == 22

    def test_policy_creation_for_audit(self):
        """Test creating a policy that would be audited."""
        policy = NetworkPolicy("test-audit-policy")
        policy.metadata.description = "Policy for audit testing"

        # Add a firewall rule
        rule = FirewallRule()
        rule.name = "allow-web"
        rule.action = Action.ALLOW
        rule.direction = Direction.INBOUND
        rule.protocol = Protocol.tcp()
        rule.ports([80, 443])
        policy.add_firewall_rule(rule)

        # Add a zone
        zone = policy.add_zone("web-tier")
        zone.add_network("192.168.100.0/24")

        # Verify policy structure
        assert policy.metadata.name == "test-audit-policy"
        assert len(policy.firewall_rules) == 1
        assert len(policy.zones) == 1
        assert "web-tier" in policy.zones

        # Verify rule
        assert policy.firewall_rules[0].name == "allow-web"
        assert len(policy.firewall_rules[0].destination_ports) == 2


class TestComplianceIssue:
    """Test cases for ComplianceIssue class."""

    def test_compliance_issue_all_fields(self):
        """Test compliance issue with all fields."""
        issue = ComplianceIssue(
            severity="critical",
            rule_id="rule-123",
            rule_name="deny-all",
            issue_type="policy_violation",
            description="Default deny rule is missing",
            device="firewall-01",
            recommendation="Add default deny rule at end of chain",
            current_config="ACCEPT all",
            expected_config="DROP all",
        )

        assert issue.severity == "critical"
        assert issue.rule_id == "rule-123"
        assert issue.rule_name == "deny-all"
        assert issue.issue_type == "policy_violation"
        assert issue.description == "Default deny rule is missing"
        assert issue.device == "firewall-01"
        assert issue.recommendation == "Add default deny rule at end of chain"
        assert issue.current_config == "ACCEPT all"
        assert issue.expected_config == "DROP all"

    def test_compliance_issue_minimal(self):
        """Test compliance issue with minimal required fields."""
        issue = ComplianceIssue(
            severity="low",
            rule_id=None,
            rule_name=None,
            issue_type="info",
            description="Informational message",
            device="192.168.1.1",
            recommendation="No action required",
        )

        assert issue.severity == "low"
        assert issue.rule_id is None
        assert issue.rule_name is None
        assert issue.issue_type == "info"
        assert issue.current_config is None
        assert issue.expected_config is None


if __name__ == "__main__":
    pytest.main([__file__])
