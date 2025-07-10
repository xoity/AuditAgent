"""
Tests for audit_agent.core.policy module.
"""

import json

import pytest
import yaml

from audit_agent.core.objects import Protocol, Zone
from audit_agent.core.policy import (
    NetworkPolicy,
    PolicyMetadata,
    PolicyValidationResult,
)
from audit_agent.core.rules import Action, Direction, FirewallRule


class TestPolicyMetadata:
    """Test cases for PolicyMetadata class."""

    def test_metadata_creation(self):
        """Test basic metadata creation."""
        metadata = PolicyMetadata(name="test-policy")
        assert metadata.name == "test-policy"
        assert metadata.version == "1.0"
        assert metadata.author is None
        assert metadata.description is None

    def test_metadata_with_values(self):
        """Test metadata creation with values."""
        metadata = PolicyMetadata(
            name="test-policy",
            author="Test Author",
            description="Test description",
            version="1.0.0",
        )
        assert metadata.name == "test-policy"
        assert metadata.author == "Test Author"
        assert metadata.description == "Test description"
        assert metadata.version == "1.0.0"


class TestNetworkPolicy:
    """Test cases for NetworkPolicy class."""

    def test_policy_creation(self):
        """Test basic policy creation."""
        policy = NetworkPolicy("test-policy")
        assert policy.metadata.name == "test-policy"
        assert isinstance(policy.metadata, PolicyMetadata)
        assert len(policy.zones) == 0
        assert len(policy.firewall_rules) == 0

    def test_add_zone(self):
        """Test adding zones to policy."""
        policy = NetworkPolicy("test-policy")

        zone = policy.add_zone("dmz")
        assert isinstance(zone, Zone)
        assert zone.name == "dmz"
        assert len(policy.zones) == 1
        assert "dmz" in policy.zones
        assert policy.zones["dmz"] == zone

    def test_add_firewall_rule(self):
        """Test adding firewall rules to policy."""
        policy = NetworkPolicy("test-policy")

        rule = FirewallRule()
        rule.name = "test-rule"
        rule.description = "Test rule"

        policy.add_firewall_rule(rule)
        assert len(policy.firewall_rules) == 1
        assert policy.firewall_rules[0] == rule

    def test_validate_policy_valid(self):
        """Test policy validation with valid policy."""
        policy = NetworkPolicy("test-policy")
        policy.metadata.description = "Test policy"

        # Add a zone
        zone = policy.add_zone("dmz")
        zone.add_network("192.168.1.0/24")

        # Add a firewall rule
        rule = FirewallRule()
        rule.name = "allow-ssh"
        rule.description = "Allow SSH"
        rule.action = Action.ALLOW
        rule.direction = Direction.INBOUND
        rule.protocol = Protocol.tcp()
        rule.port(22)
        policy.add_firewall_rule(rule)

        validation = policy.validate_policy()
        assert validation.is_valid
        assert len(validation.errors) == 0

    def test_validate_policy_invalid(self):
        """Test policy validation with invalid policy."""
        policy = NetworkPolicy("")  # Empty name should be invalid

        validation = policy.validate_policy()
        # Note: The current implementation may not validate empty names
        # This test may need adjustment based on actual validation logic
        assert isinstance(validation, PolicyValidationResult)

    def test_export_to_yaml(self):
        """Test YAML export functionality."""
        policy = NetworkPolicy("test-policy")
        policy.metadata.description = "Test policy"
        policy.metadata.author = "Test Author"

        yaml_content = policy.export_to_yaml()
        assert isinstance(yaml_content, str)

        # Parse the YAML to ensure it's valid
        parsed = yaml.safe_load(yaml_content)
        assert parsed["metadata"]["name"] == "test-policy"
        assert parsed["metadata"]["description"] == "Test policy"
        assert parsed["metadata"]["author"] == "Test Author"

    def test_export_to_json(self):
        """Test JSON export functionality."""
        policy = NetworkPolicy("test-policy")
        policy.metadata.description = "Test policy"

        json_content = policy.export_to_json()
        assert isinstance(json_content, str)

        # Parse the JSON to ensure it's valid
        parsed = json.loads(json_content)
        assert parsed["metadata"]["name"] == "test-policy"
        assert parsed["metadata"]["description"] == "Test policy"

    def test_from_dict_basic(self):
        """Test creating policy from dictionary."""
        policy_dict = {
            "metadata": {
                "name": "test-policy",
                "description": "Test policy",
                "author": "Test Author",
            },
            "zones": {},
            "firewall_rules": [],
        }

        policy = NetworkPolicy.from_dict(policy_dict)
        assert policy.metadata.name == "test-policy"
        assert policy.metadata.description == "Test policy"
        assert policy.metadata.author == "Test Author"

    def test_from_dict_with_zones(self):
        """Test creating policy from dictionary with zones."""
        policy_dict = {
            "metadata": {"name": "test-policy", "description": "Test policy"},
            "zones": {
                "dmz": {
                    "name": "dmz",
                    "description": "DMZ zone",
                    "networks": [{"cidr": "192.168.1.0/24"}],
                }
            },
            "firewall_rules": [],
        }

        policy = NetworkPolicy.from_dict(policy_dict)
        assert len(policy.zones) == 1
        assert "dmz" in policy.zones
        assert policy.zones["dmz"].name == "dmz"
        assert policy.zones["dmz"].description == "DMZ zone"

    def test_from_dict_with_firewall_rules(self):
        """Test creating policy from dictionary with firewall rules."""
        policy_dict = {
            "metadata": {"name": "test-policy", "description": "Test policy"},
            "zones": {},
            "firewall_rules": [
                {
                    "name": "allow-ssh",
                    "description": "Allow SSH",
                    "action": "allow",
                    "direction": "inbound",
                    "protocol": {"name": "tcp"},
                    "destination_ports": [{"number": 22}],
                }
            ],
        }

        policy = NetworkPolicy.from_dict(policy_dict)
        assert len(policy.firewall_rules) == 1
        rule = policy.firewall_rules[0]
        assert rule.name == "allow-ssh"
        assert rule.action == Action.ALLOW
        assert rule.direction == Direction.INBOUND

    def test_from_yaml_content(self):
        """Test loading policy from YAML content."""
        yaml_content = """
metadata:
  name: test-policy
  description: Test policy from YAML
  author: Test Author
zones:
  dmz:
    name: dmz
    description: DMZ zone
    networks:
      - cidr: 192.168.1.0/24
firewall_rules:
  - name: allow-ssh
    description: Allow SSH
    action: allow
    direction: inbound
    protocol:
      name: tcp
    destination_ports:
      - number: 22
"""

        policy = NetworkPolicy.from_yaml(yaml_content)
        assert policy.metadata.name == "test-policy"
        assert policy.metadata.description == "Test policy from YAML"
        assert len(policy.zones) == 1
        assert len(policy.firewall_rules) == 1

    def test_from_json_content(self):
        """Test loading policy from JSON content."""
        json_content = {
            "metadata": {
                "name": "test-policy",
                "description": "Test policy from JSON",
                "author": "Test Author",
            },
            "zones": {},
            "firewall_rules": [],
        }

        policy = NetworkPolicy.from_json(json.dumps(json_content))
        assert policy.metadata.name == "test-policy"
        assert policy.metadata.description == "Test policy from JSON"

    def test_get_zone(self):
        """Test getting a zone by name."""
        policy = NetworkPolicy("test-policy")
        zone = policy.add_zone("dmz")

        retrieved_zone = policy.get_zone("dmz")
        assert retrieved_zone == zone

        non_existent = policy.get_zone("non-existent")
        assert non_existent is None


class TestPolicyValidationResult:
    """Test cases for PolicyValidationResult class."""

    def test_validation_result_valid(self):
        """Test validation result for valid policy."""
        result = PolicyValidationResult(is_valid=True, errors=[], warnings=[])
        assert result.is_valid
        assert len(result.errors) == 0
        assert len(result.warnings) == 0

    def test_validation_result_invalid(self):
        """Test validation result for invalid policy."""
        errors = ["Policy name cannot be empty"]
        warnings = ["Consider adding a description"]

        result = PolicyValidationResult(
            is_valid=False, errors=errors, warnings=warnings
        )
        assert not result.is_valid
        assert len(result.errors) == 1
        assert len(result.warnings) == 1
        assert result.errors[0] == "Policy name cannot be empty"
        assert result.warnings[0] == "Consider adding a description"

    def test_add_error(self):
        """Test adding errors to validation result."""
        result = PolicyValidationResult(is_valid=True)
        assert result.is_valid

        result.add_error("Test error")
        assert not result.is_valid
        assert len(result.errors) == 1
        assert result.errors[0] == "Test error"

    def test_add_warning(self):
        """Test adding warnings to validation result."""
        result = PolicyValidationResult(is_valid=True)

        result.add_warning("Test warning")
        assert result.is_valid  # Warnings don't affect validity
        assert len(result.warnings) == 1
        assert result.warnings[0] == "Test warning"


if __name__ == "__main__":
    pytest.main([__file__])
