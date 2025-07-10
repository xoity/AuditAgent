"""
Audit engine for comparing policies against device configurations.
"""

from typing import List, Optional
from pydantic import BaseModel
from dataclasses import dataclass
from ..core.policy import NetworkPolicy
from ..core.rules import BaseRule, FirewallRule
from ..devices.base import NetworkDevice, ConfigurationItem
import datetime


@dataclass
class ComplianceIssue:
    """Represents a compliance issue found during audit."""

    severity: str  # "critical", "high", "medium", "low", "info"
    rule_id: Optional[str]
    rule_name: Optional[str]
    issue_type: (
        str  # "missing_rule", "extra_rule", "misconfigured_rule", "policy_violation"
    )
    description: str
    device: str
    recommendation: str
    current_config: Optional[str] = None
    expected_config: Optional[str] = None


@dataclass
class DeviceAuditResult:
    """Audit results for a single device."""

    device: NetworkDevice
    total_rules_checked: int
    compliant_rules: int
    non_compliant_rules: int
    issues: List[ComplianceIssue]
    compliance_percentage: float
    audit_timestamp: str

    @property
    def is_compliant(self) -> bool:
        """Check if device is fully compliant."""
        return self.non_compliant_rules == 0


class PolicyAuditResult(BaseModel):
    """Complete audit results for a policy across multiple devices."""

    model_config = {"arbitrary_types_allowed": True}

    policy_name: str
    devices_audited: int
    compliant_devices: int
    non_compliant_devices: int
    total_issues: int
    device_results: List[DeviceAuditResult] = []
    overall_compliance_percentage: float
    audit_timestamp: str

    @property
    def is_compliant(self) -> bool:
        """Check if all devices are compliant."""
        return self.non_compliant_devices == 0

    def get_issues_by_severity(self, severity: str) -> List[ComplianceIssue]:
        """Get all issues of a specific severity."""
        issues = []
        for device_result in self.device_results:
            issues.extend(
                [issue for issue in device_result.issues if issue.severity == severity]
            )
        return issues

    def get_critical_issues(self) -> List[ComplianceIssue]:
        """Get all critical issues."""
        return self.get_issues_by_severity("critical")

    def get_high_issues(self) -> List[ComplianceIssue]:
        """Get all high severity issues."""
        return self.get_issues_by_severity("high")


class RuleComparer:
    """Compares policy rules with device configurations."""

    def __init__(self):
        pass

    def compare_firewall_rule(
        self, policy_rule: FirewallRule, device_config: List[ConfigurationItem]
    ) -> List[ComplianceIssue]:
        """Compare a policy firewall rule with device configuration."""
        issues = []

        # Find matching rules in device configuration
        matching_rules = self._find_matching_firewall_rules(policy_rule, device_config)

        if not matching_rules:
            # Rule is missing from device
            issues.append(
                ComplianceIssue(
                    severity="high",
                    rule_id=policy_rule.id,
                    rule_name=policy_rule.name,
                    issue_type="missing_rule",
                    description=f"Required firewall rule '{policy_rule.name or policy_rule.id}' is missing from device",
                    device="",  # Will be set by caller
                    recommendation="Add the missing firewall rule to the device configuration",
                    expected_config=str(policy_rule),
                )
            )
        else:
            # Check if existing rules match the policy
            for device_rule in matching_rules:
                rule_issues = self._validate_firewall_rule_match(
                    policy_rule, device_rule
                )
                issues.extend(rule_issues)

        return issues

    def _find_matching_firewall_rules(
        self, policy_rule: FirewallRule, device_config: List[ConfigurationItem]
    ) -> List[ConfigurationItem]:
        """Find device configuration items that might match a policy rule."""
        candidates = []

        # Get firewall rules from device config
        firewall_rules = [
            item for item in device_config if item.type == "firewall_rule"
        ]

        for rule in firewall_rules:
            if self._rules_might_match(policy_rule, rule):
                candidates.append(rule)

        return candidates

    def _rules_might_match(
        self, policy_rule: FirewallRule, device_rule: ConfigurationItem
    ) -> bool:
        """Check if a policy rule and device rule might be related."""
        # This is a simplified matching logic
        # In practice, this would need to parse the device rule content
        # and compare it with the policy rule attributes

        device_content = device_rule.content.lower()

        # Check if action matches
        action_keywords = {
            "allow": ["permit", "allow"],
            "deny": ["deny", "drop", "reject"],
            "drop": ["deny", "drop"],
            "reject": ["reject", "deny"],
        }

        policy_action = policy_rule.action.value
        if policy_action in action_keywords:
            action_found = any(
                keyword in device_content for keyword in action_keywords[policy_action]
            )
            if not action_found:
                return False

        # Check protocol if specified
        if policy_rule.protocol and policy_rule.protocol.name != "any":
            if policy_rule.protocol.name not in device_content:
                return False

        # Check for IP addresses
        if policy_rule.source_ips:
            # Simplified check - look for any IP in the device rule
            for ip in policy_rule.source_ips:
                ip_str = str(ip)
                if ip_str not in device_content and "any" not in device_content:
                    continue

        return True

    def _validate_firewall_rule_match(
        self, policy_rule: FirewallRule, device_rule: ConfigurationItem
    ) -> List[ComplianceIssue]:
        """Validate that a device rule properly implements a policy rule."""
        issues = []

        # This would contain detailed validation logic
        # For now, we'll do basic checks

        device_content = device_rule.content.lower()

        # Check logging requirement
        if policy_rule.log_traffic and "log" not in device_content:
            issues.append(
                ComplianceIssue(
                    severity="medium",
                    rule_id=policy_rule.id,
                    rule_name=policy_rule.name,
                    issue_type="misconfigured_rule",
                    description=f"Rule '{policy_rule.name or policy_rule.id}' requires logging but device rule doesn't have logging enabled",
                    device="",
                    recommendation="Add logging to the firewall rule",
                    current_config=device_rule.content,
                    expected_config=f"{device_rule.content} log",
                )
            )

        return issues

    def find_extra_rules(
        self, policy_rules: List[BaseRule], device_config: List[ConfigurationItem]
    ) -> List[ComplianceIssue]:
        """Find rules on device that are not defined in policy."""
        issues = []

        # Get all firewall rules from device
        device_firewall_rules = [
            item for item in device_config if item.type == "firewall_rule"
        ]
        policy_firewall_rules = [
            rule for rule in policy_rules if isinstance(rule, FirewallRule)
        ]

        for device_rule in device_firewall_rules:
            if not self._device_rule_covered_by_policy(
                device_rule, policy_firewall_rules
            ):
                issues.append(
                    ComplianceIssue(
                        severity="medium",
                        rule_id=None,
                        rule_name=None,
                        issue_type="extra_rule",
                        description=f"Device has extra firewall rule not defined in policy: {device_rule.content}",
                        device="",
                        recommendation="Review if this rule is necessary or add it to the policy",
                        current_config=device_rule.content,
                    )
                )

        return issues

    def _device_rule_covered_by_policy(
        self, device_rule: ConfigurationItem, policy_rules: List[FirewallRule]
    ) -> bool:
        """Check if a device rule is covered by any policy rule."""
        for policy_rule in policy_rules:
            if self._rules_might_match(policy_rule, device_rule):
                return True
        return False


class AuditEngine:
    """Main audit engine for policy compliance checking."""

    def __init__(self):
        self.rule_comparer = RuleComparer()

    async def audit_policy(
        self, policy: NetworkPolicy, devices: List[NetworkDevice]
    ) -> PolicyAuditResult:
        """Audit a policy against multiple devices."""
        device_results = []
        total_issues = 0
        compliant_devices = 0

        for device in devices:
            device_result = await self.audit_device(policy, device)
            device_results.append(device_result)
            total_issues += len(device_result.issues)

            if device_result.is_compliant:
                compliant_devices += 1

        # Calculate overall compliance
        overall_compliance = (
            (compliant_devices / len(devices) * 100) if devices else 100
        )

        return PolicyAuditResult(
            policy_name=policy.metadata.name,
            devices_audited=len(devices),
            compliant_devices=compliant_devices,
            non_compliant_devices=len(devices) - compliant_devices,
            total_issues=total_issues,
            device_results=device_results,
            overall_compliance_percentage=overall_compliance,
            audit_timestamp=datetime.datetime.now().isoformat(),
        )

    async def audit_device(
        self, policy: NetworkPolicy, device: NetworkDevice
    ) -> DeviceAuditResult:
        """Audit a single device against a policy."""
        issues = []

        # Get device configuration
        try:
            if not device.is_connected:
                await device.connect()

            device_config = await device.get_configuration()
            config_items = device_config.parsed_items

        except Exception as e:
            # If we can't get the configuration, that's a critical issue
            issues.append(
                ComplianceIssue(
                    severity="critical",
                    rule_id=None,
                    rule_name=None,
                    issue_type="connectivity_error",
                    description=f"Failed to retrieve configuration from device: {str(e)}",
                    device=str(device),
                    recommendation="Check device connectivity and credentials",
                )
            )

            return DeviceAuditResult(
                device=device,
                total_rules_checked=0,
                compliant_rules=0,
                non_compliant_rules=0,
                issues=issues,
                compliance_percentage=0.0,
                audit_timestamp=datetime.datetime.now().isoformat(),
            )

        # Check each policy rule against device configuration
        all_policy_rules = policy.get_enabled_rules()
        total_rules = len(all_policy_rules)
        compliant_rules = 0

        for rule in all_policy_rules:
            rule_issues = []

            if isinstance(rule, FirewallRule):
                rule_issues = self.rule_comparer.compare_firewall_rule(
                    rule, config_items
                )
            # Add other rule types as needed

            # Set device name for all issues
            for issue in rule_issues:
                issue.device = str(device)

            issues.extend(rule_issues)

            # If no issues found for this rule, it's compliant
            if not rule_issues:
                compliant_rules += 1

        # Check for extra rules not in policy
        extra_rule_issues = self.rule_comparer.find_extra_rules(
            all_policy_rules, config_items
        )
        for issue in extra_rule_issues:
            issue.device = str(device)
        issues.extend(extra_rule_issues)

        # Calculate compliance percentage
        non_compliant_rules = total_rules - compliant_rules
        compliance_percentage = (
            (compliant_rules / total_rules * 100) if total_rules > 0 else 100
        )

        return DeviceAuditResult(
            device=device,
            total_rules_checked=total_rules,
            compliant_rules=compliant_rules,
            non_compliant_rules=non_compliant_rules,
            issues=issues,
            compliance_percentage=compliance_percentage,
            audit_timestamp=datetime.datetime.now().isoformat(),
        )

    def generate_audit_report(
        self, audit_result: PolicyAuditResult, format: str = "text"
    ) -> str:
        """Generate a human-readable audit report."""
        if format == "text":
            return self._generate_text_report(audit_result)
        elif format == "html":
            return self._generate_html_report(audit_result)
        elif format == "json":
            return audit_result.json(indent=2)
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def _generate_text_report(self, audit_result: PolicyAuditResult) -> str:
        """Generate a text-based audit report."""
        report = []
        report.append("=" * 80)
        report.append("NETWORK SECURITY POLICY AUDIT REPORT")
        report.append("=" * 80)
        report.append("")
        report.append(f"Policy: {audit_result.policy_name}")
        report.append(f"Audit Date: {audit_result.audit_timestamp}")
        report.append(
            f"Overall Compliance: {audit_result.overall_compliance_percentage:.1f}%"
        )
        report.append("")
        report.append(f"Devices Audited: {audit_result.devices_audited}")
        report.append(f"Compliant Devices: {audit_result.compliant_devices}")
        report.append(f"Non-Compliant Devices: {audit_result.non_compliant_devices}")
        report.append(f"Total Issues Found: {audit_result.total_issues}")
        report.append("")

        # Summary by severity
        critical_issues = audit_result.get_critical_issues()
        high_issues = audit_result.get_high_issues()

        report.append("ISSUE SUMMARY BY SEVERITY:")
        report.append(f"  Critical: {len(critical_issues)}")
        report.append(f"  High: {len(high_issues)}")
        report.append(f"  Medium: {len(audit_result.get_issues_by_severity('medium'))}")
        report.append(f"  Low: {len(audit_result.get_issues_by_severity('low'))}")
        report.append("")

        # Device details
        report.append("DEVICE AUDIT RESULTS:")
        report.append("-" * 40)

        for device_result in audit_result.device_results:
            report.append(f"Device: {device_result.device}")
            report.append(f"  Compliance: {device_result.compliance_percentage:.1f}%")
            report.append(f"  Issues: {len(device_result.issues)}")

            if device_result.issues:
                report.append("  Critical Issues:")
                for issue in device_result.issues:
                    if issue.severity == "critical":
                        report.append(f"    - {issue.description}")

                report.append("  High Priority Issues:")
                for issue in device_result.issues:
                    if issue.severity == "high":
                        report.append(f"    - {issue.description}")

            report.append("")

        return "\n".join(report)

    def _generate_html_report(self, audit_result: PolicyAuditResult) -> str:
        """Generate an HTML audit report."""
        # This would generate a full HTML report
        # For brevity, returning a simple HTML structure
        return f"""
        <html>
        <head><title>Audit Report - {audit_result.policy_name}</title></head>
        <body>
        <h1>Network Security Policy Audit Report</h1>
        <h2>Policy: {audit_result.policy_name}</h2>
        <p>Overall Compliance: {audit_result.overall_compliance_percentage:.1f}%</p>
        <p>Total Issues: {audit_result.total_issues}</p>
        <!-- More detailed HTML content would go here -->
        </body>
        </html>
        """
