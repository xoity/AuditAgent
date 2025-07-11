"""
Network Security Policy definition and management.
"""

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel

from .objects import Zone
from .rules import BaseRule, FirewallRule, NATRule, QoSRule, VPNRule


class PolicyMetadata(BaseModel):
    """Metadata for a network policy."""

    name: str
    version: str = "1.0"
    description: Optional[str] = None
    author: Optional[str] = None
    created_date: Optional[str] = None
    last_modified: Optional[str] = None
    tags: List[str] = []


class PolicyValidationResult(BaseModel):
    """Result of policy validation."""

    is_valid: bool
    errors: List[str] = []
    warnings: List[str] = []

    def add_error(self, error: str) -> None:
        """Add a validation error."""
        self.errors.append(error)
        self.is_valid = False

    def add_warning(self, warning: str) -> None:
        """Add a validation warning."""
        self.warnings.append(warning)


class NetworkPolicy(BaseModel):
    """
    Represents a complete network security policy.

    This is the main class for defining declarative network security policies.
    """

    metadata: PolicyMetadata
    zones: Dict[str, Zone] = {}
    firewall_rules: List[FirewallRule] = []
    nat_rules: List[NATRule] = []
    vpn_rules: List[VPNRule] = []
    qos_rules: List[QoSRule] = []
    global_settings: Dict[str, Any] = {}

    def __init__(self, name: str, **kwargs):
        """Initialize a new network policy."""
        if "metadata" not in kwargs:
            kwargs["metadata"] = PolicyMetadata(name=name)
        super().__init__(**kwargs)

    def add_zone(self, zone: Union[str, Zone]) -> Zone:
        """Add a zone to the policy."""
        if isinstance(zone, str):
            zone = Zone(name=zone)
        self.zones[zone.name] = zone
        return zone

    def get_zone(self, name: str) -> Optional[Zone]:
        """Get a zone by name."""
        return self.zones.get(name)

    def add_rule(self, rule: BaseRule) -> None:
        """Add a rule to the policy."""
        if isinstance(rule, FirewallRule):
            self.firewall_rules.append(rule)
        elif isinstance(rule, NATRule):
            self.nat_rules.append(rule)
        elif isinstance(rule, VPNRule):
            self.vpn_rules.append(rule)
        elif isinstance(rule, QoSRule):
            self.qos_rules.append(rule)
        else:
            raise ValueError(f"Unsupported rule type: {type(rule)}")

    def add_firewall_rule(self, rule: FirewallRule) -> None:
        """Add a firewall rule."""
        self.firewall_rules.append(rule)

    def add_nat_rule(self, rule: NATRule) -> None:
        """Add a NAT rule."""
        self.nat_rules.append(rule)

    def add_vpn_rule(self, rule: VPNRule) -> None:
        """Add a VPN rule."""
        self.vpn_rules.append(rule)

    def add_qos_rule(self, rule: QoSRule) -> None:
        """Add a QoS rule."""
        self.qos_rules.append(rule)

    def get_all_rules(self) -> List[BaseRule]:
        """Get all rules in the policy."""
        all_rules = []
        all_rules.extend(self.firewall_rules)
        all_rules.extend(self.nat_rules)
        all_rules.extend(self.vpn_rules)
        all_rules.extend(self.qos_rules)
        return all_rules

    def get_rules_by_tag(self, tag: str) -> List[BaseRule]:
        """Get all rules with a specific tag."""
        return [rule for rule in self.get_all_rules() if tag in rule.tags]

    def get_enabled_rules(self) -> List[BaseRule]:
        """Get all enabled rules."""
        return [rule for rule in self.get_all_rules() if rule.enabled]

    def validate_policy(self) -> PolicyValidationResult:
        """Validate the policy for consistency and correctness."""
        result = PolicyValidationResult(is_valid=True)

        # Check for rule conflicts
        self._validate_rule_conflicts(result)

        # Check zone references
        self._validate_zone_references(result)

        # Check for unreachable rules
        self._validate_rule_reachability(result)

        # Check for security best practices
        self._validate_security_practices(result)

        return result

    def _validate_rule_conflicts(self, result: PolicyValidationResult) -> None:
        """Check for conflicting rules."""
        # Sort firewall rules by priority
        sorted_rules = sorted(self.firewall_rules, key=lambda r: r.priority)

        for i, rule1 in enumerate(sorted_rules):
            for rule2 in sorted_rules[i + 1 :]:
                if self._rules_conflict(rule1, rule2):
                    result.add_warning(
                        f"Rules may conflict: '{rule1.name or rule1.id}' and '{rule2.name or rule2.id}'"
                    )

    def _validate_zone_references(self, result: PolicyValidationResult) -> None:
        """Check that all zone references are valid."""
        for rule in self.firewall_rules:
            for zone in rule.source_zones + rule.destination_zones:
                if zone.name not in self.zones:
                    result.add_error(f"Rule references undefined zone: '{zone.name}'")

    def _validate_rule_reachability(self, result: PolicyValidationResult) -> None:
        """Check for unreachable rules."""
        # This is a simplified check - in practice, this would be more complex
        sorted_rules = sorted(self.firewall_rules, key=lambda r: r.priority)

        for i, rule in enumerate(sorted_rules):
            if not rule.enabled:
                continue

            # Check if any previous rule would block this one
            for prev_rule in sorted_rules[:i]:
                if (
                    prev_rule.enabled
                    and prev_rule.action.value in ["deny", "drop"]
                    and self._rule_subsumes(prev_rule, rule)
                ):
                    result.add_warning(
                        f"Rule '{rule.name or rule.id}' may be unreachable due to "
                        f"higher priority rule '{prev_rule.name or prev_rule.id}'"
                    )
                    break

    def _validate_security_practices(self, result: PolicyValidationResult) -> None:
        """Check for security best practices."""
        # Check for overly permissive rules
        for rule in self.firewall_rules:
            if (
                rule.action.value == "allow"
                and any(str(ip) == "0.0.0.0/0" for ip in rule.source_ips)
                and any(str(ip) == "0.0.0.0/0" for ip in rule.destination_ips)
            ):
                result.add_warning(
                    f"Rule '{rule.name or rule.id}' allows traffic from any source to any destination"
                )

            # Check for rules without logging on deny actions
            if rule.action.value in ["deny", "drop"] and not rule.log_traffic:
                result.add_warning(
                    f"Deny/drop rule '{rule.name or rule.id}' should enable logging"
                )

    def _rules_conflict(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """Check if two firewall rules conflict."""
        # Simplified conflict detection
        if rule1.action != rule2.action and rule1.priority == rule2.priority:
            # Same priority but different actions might conflict
            return self._rules_overlap(rule1, rule2)
        return False

    def _rule_subsumes(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """Check if rule1 completely subsumes rule2."""
        # Simplified subsumption check
        return self._rules_overlap(rule1, rule2)

    def _rules_overlap(self, rule1: FirewallRule, rule2: FirewallRule) -> bool:
        """Check if two rules have overlapping traffic patterns."""
        # This is a simplified check - real implementation would be more thorough

        # Check protocol overlap
        if (
            rule1.protocol
            and rule2.protocol
            and rule1.protocol.name != "any"
            and rule2.protocol.name != "any"
            and rule1.protocol.name != rule2.protocol.name
        ):
            return False

        # Check direction overlap
        if (
            rule1.direction != rule2.direction
            and rule1.direction != "bidirectional"
            and rule2.direction != "bidirectional"
        ):
            return False

        # If we get here, there's potential overlap
        return True

    def export_to_dict(self) -> Dict[str, Any]:
        """Export policy to dictionary format."""
        return self.model_dump()

    def export_to_yaml(self) -> str:
        """Export policy to YAML format."""
        import yaml

        # Convert Pydantic model to dict with proper serialization
        data = self.model_dump(mode="python")

        # Custom representer for enum values
        def represent_enum(dumper, data):
            return dumper.represent_scalar("tag:yaml.org,2002:str", data.value)

        yaml.add_representer(
            object, lambda dumper, data: dumper.represent_str(str(data))
        )

        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

    def export_to_json(self) -> str:
        """Export policy to JSON format."""
        return self.model_dump_json(indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NetworkPolicy":
        """Create policy from dictionary."""
        # Extract name from metadata if available
        metadata = data.get("metadata", {})
        name = metadata.get("name", "unnamed-policy")

        # Remove metadata from data to avoid conflicts
        data_copy = data.copy()
        if "metadata" in data_copy:
            del data_copy["metadata"]

        # Create policy with name and metadata
        policy = cls(name=name, **data_copy)

        # Update metadata if provided
        if metadata:
            for key, value in metadata.items():
                if hasattr(policy.metadata, key):
                    setattr(policy.metadata, key, value)

        return policy

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "NetworkPolicy":
        """Create policy from YAML content."""
        import yaml

        data = yaml.safe_load(yaml_content)
        return cls.from_dict(data)

    @classmethod
    def from_json(cls, json_content: str) -> "NetworkPolicy":
        """Create policy from JSON content."""
        import json

        data = json.loads(json_content)
        return cls.from_dict(data)

    def audit(self, devices: List[Any]) -> Any:
        """Audit the policy against actual device configurations."""

        from ..audit.engine import AuditEngine

        audit_engine = AuditEngine()
        import asyncio

        return asyncio.run(audit_engine.audit_policy(self, devices))

    def enforce(self, devices: List[Any], dry_run: bool = False) -> Any:
        """Enforce the policy on the given devices."""

        from ..enforcement.engine import EnforcementEngine

        enforcement_engine = EnforcementEngine()
        import asyncio

        return asyncio.run(
            enforcement_engine.enforce_policy(self, devices, dry_run=dry_run)
        )
