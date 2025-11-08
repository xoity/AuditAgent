"""
Audit engine for comparing policies against device configurations.
"""

import datetime
from dataclasses import dataclass
from typing import List, Optional, Union

from pydantic import BaseModel

from ..core.logging_config import get_logger
from ..core.policy import NetworkPolicy
from ..core.rules import BaseRule, FirewallRule
from ..devices.base import ConfigurationItem, NetworkDevice

logger = get_logger(__name__)


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
    expected_config: Optional[Union[str, "FirewallRule"]] = None


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

        # Store device config for use in helper methods
        self._current_device_config = device_config

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
                    expected_config=policy_rule,
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
        # Parse iptables rule from device
        device_content = device_rule.content.lower()

        # Extract key components from the iptables rule
        # Example: "-A INPUT -p tcp -s 0.0.0.0/0 -d 192.168.0.165/32 --dport 22 -j ACCEPT"

        logger.debug(
            "Comparing policy rule '%s' with device rule: %s",
            policy_rule.name,
            device_content,
        )

        # Check action match
        policy_action = policy_rule.action.value.lower()
        device_has_accept = "-j accept" in device_content
        device_has_drop = "-j drop" in device_content or "-j deny" in device_content
        device_has_reject = "-j reject" in device_content

        action_matches = False
        if policy_action == "allow" and device_has_accept:
            action_matches = True
        elif policy_action in ["deny", "drop"] and (
            device_has_drop or device_has_reject
        ):
            action_matches = True
        elif policy_action == "reject" and device_has_reject:
            action_matches = True

        logger.debug(
            "Action match: policy=%s, device_accept=%s, matches=%s",
            policy_action,
            device_has_accept,
            action_matches,
        )
        if not action_matches:
            return False

        # Check direction - look for chain information
        # iptables-save format: "-A INPUT ..." or device shows "input" chain context
        if policy_rule.direction.value == "inbound":
            # Look for INPUT chain references (both -A INPUT and section info)
            input_in_content = "-a input" in device_content
            input_in_section = (
                device_rule.section and "input" in device_rule.section.lower()
            )
            if not (input_in_content or input_in_section):
                logger.debug(
                    "Direction mismatch: expected inbound/INPUT but device rule doesn't match"
                )
                return False
        elif policy_rule.direction.value == "outbound":
            # Look for OUTPUT chain references
            output_in_content = "-a output" in device_content
            output_in_section = (
                device_rule.section and "output" in device_rule.section.lower()
            )
            if not (output_in_content or output_in_section):
                logger.debug(
                    "Direction mismatch: expected outbound/OUTPUT but device rule doesn't match"
                )
                return False

        # Check protocol
        if policy_rule.protocol and policy_rule.protocol.name != "any":
            protocol_check = f"-p {policy_rule.protocol.name}"
            if protocol_check not in device_content:
                logger.debug(
                    "Protocol mismatch: expected %s not found in device rule",
                    protocol_check,
                )
                return False

        # Check destination ports
        if policy_rule.destination_ports:
            port = policy_rule.destination_ports[0]
            if port.is_single():
                port_check = f"--dport {port.number}"
                if port_check not in device_content:
                    logger.debug(
                        "Port mismatch: expected %s not found in device rule",
                        port_check,
                    )
                    return False

        # Check source IPs (simplified)
        if policy_rule.source_ips:
            source_ip = policy_rule.source_ips[0]
            # Use string conversion which works for both IPAddress and IPRange
            ip_str = str(source_ip)

            # Check if source IP is in the device rule
            # Special case: 0.0.0.0/0 means "any" and may be omitted in iptables rules
            if ip_str == "0.0.0.0/0":
                # For "any" source, either -s 0.0.0.0/0 should be present OR no -s flag at all
                source_check = f"-s {ip_str}"
                if source_check not in device_content and "-s " not in device_content:
                    # No source restriction means it accepts from any source (0.0.0.0/0)
                    logger.debug(
                        "Source IP 0.0.0.0/0 (any) matches - no source restriction in device rule"
                    )
                else:
                    logger.debug(
                        "Source IP mismatch: expected %s not found in device rule",
                        source_check,
                    )
                    return False
            else:
                # Specific source IP must be present
                source_check = f"-s {ip_str}"
                if source_check not in device_content:
                    logger.debug(
                        "Source IP mismatch: expected %s not found in device rule",
                        source_check,
                    )
                    return False

        # Check destination IPs (simplified)
        if policy_rule.destination_ips:
            dest_ip = policy_rule.destination_ips[0]
            # Use string conversion which works for both IPAddress and IPRange
            ip_str = str(dest_ip)

            # Check if destination IP is in the device rule
            dest_check = f"-d {ip_str}"
            if dest_check not in device_content:
                logger.debug(
                    "Destination IP mismatch: expected %s not found in device rule",
                    dest_check,
                )
                return False

        logger.debug("Rule match successful for policy rule '%s'", policy_rule.name)
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
            # Check if there's a corresponding LOG rule for this policy rule
            if not self._has_corresponding_log_rule(policy_rule, device_rule):
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

    def _has_corresponding_log_rule(
        self, policy_rule: FirewallRule, device_rule: ConfigurationItem
    ) -> bool:
        """Check if there's a corresponding LOG rule for a policy rule."""
        # This method needs access to all device rules to check for LOG rules
        # For now, we'll set this in the compare_firewall_rule method
        if hasattr(self, "_current_device_config"):
            device_config = self._current_device_config

            # Look for LOG rules that match this policy rule
            for config_item in device_config:
                if (
                    config_item.type == "firewall_rule"
                    and "log" in config_item.content.lower()
                ):
                    # Check if this LOG rule corresponds to the policy rule
                    if self._log_rule_matches_policy(
                        policy_rule, config_item, device_rule
                    ):
                        return True

        return False

    def _log_rule_matches_policy(
        self,
        policy_rule: FirewallRule,
        log_rule: ConfigurationItem,
        main_rule: ConfigurationItem,
    ) -> bool:
        """Check if a LOG rule matches a policy rule."""
        log_content = log_rule.content.lower()

        # Check if log rule has the policy rule name in the prefix
        if policy_rule.name and f"[{policy_rule.name}]" in log_content:
            return True

        # Check if the LOG rule has similar parameters to the main rule
        main_content = main_rule.content.lower()

        # Extract key components from both rules and compare
        # This is a simplified comparison - in practice, you'd want more robust parsing

        # Check if they have the same chain
        main_chain = self._extract_chain_from_rule(main_content)
        log_chain = self._extract_chain_from_rule(log_content)

        if main_chain != log_chain:
            return False

        # Check if they have similar IP/port patterns
        # This is a heuristic - LOG rules should have similar patterns to their corresponding main rules
        main_parts = main_content.split()
        log_parts = log_content.split()

        # Look for common IP addresses or ports
        common_elements = set(main_parts) & set(log_parts)

        # If they share several common elements (IPs, ports, protocols), they likely match
        return len(common_elements) > 3

    def _extract_chain_from_rule(self, rule_content: str) -> str:
        """Extract the chain name from an iptables rule."""
        if "-a input" in rule_content:
            return "input"
        elif "-a output" in rule_content:
            return "output"
        elif "-a forward" in rule_content:
            return "forward"
        return "unknown"

    def _is_log_rule_for_policy(
        self, device_rule: ConfigurationItem, policy_rules: List[FirewallRule]
    ) -> bool:
        """Check if a device rule is a LOG rule that corresponds to a policy rule."""
        device_content = device_rule.content.lower()

        # Check if this is a LOG rule
        if "-j log" not in device_content:
            return False

        # Check if any policy rule with logging enabled could match this LOG rule
        for policy_rule in policy_rules:
            if policy_rule.log_traffic:
                # Check if the LOG rule has the policy rule name in the prefix
                if policy_rule.name and f"[{policy_rule.name}]" in device_content:
                    return True

                # Check if the LOG rule matches the policy rule's parameters
                if self._log_rule_matches_policy_rule(device_rule, policy_rule):
                    return True

        return False

    def _log_rule_matches_policy_rule(
        self, log_rule: ConfigurationItem, policy_rule: FirewallRule
    ) -> bool:
        """Check if a LOG rule matches a policy rule's parameters."""
        log_content = log_rule.content.lower()

        # Check direction/chain
        if policy_rule.direction.value == "inbound" and "-a input" not in log_content:
            return False
        elif (
            policy_rule.direction.value == "outbound" and "-a output" not in log_content
        ):
            return False

        # Check protocol
        if policy_rule.protocol and policy_rule.protocol.name != "any":
            protocol_check = f"-p {policy_rule.protocol.name}"
            if protocol_check not in log_content:
                return False

        # Check destination ports
        if policy_rule.destination_ports:
            port = policy_rule.destination_ports[0]
            if port.is_single():
                port_check = f"--dport {port.number}"
                if port_check not in log_content:
                    return False

        # Check source IPs
        if policy_rule.source_ips:
            source_ip = policy_rule.source_ips[0]
            ip_str = str(source_ip)
            if ip_str != "0.0.0.0/0":  # Skip "any" source check
                source_check = f"-s {ip_str}"
                if source_check not in log_content:
                    return False

        # Check destination IPs
        if policy_rule.destination_ips:
            dest_ip = policy_rule.destination_ips[0]
            ip_str = str(dest_ip)
            dest_check = f"-d {ip_str}"
            if dest_check not in log_content:
                return False

        return True

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

        # Store device config for use in helper methods
        self._current_device_config = device_config

        for device_rule in device_firewall_rules:
            # Skip Docker-related rules unless they conflict with policy
            if self._is_docker_related_rule(
                device_rule.content
            ) and not self._conflicts_with_policy(device_rule, policy_firewall_rules):
                logger.debug("Skipping Docker-related rule: %s", device_rule.content)
                continue

            # Skip LOG rules that correspond to policy rules with logging enabled
            if self._is_log_rule_for_policy(device_rule, policy_firewall_rules):
                logger.debug(
                    "Skipping LOG rule that corresponds to policy: %s",
                    device_rule.content,
                )
                continue

            if not self._device_rule_covered_by_policy(
                device_rule, policy_firewall_rules
            ):
                # Determine severity based on rule type
                severity = (
                    "low" if self._is_system_rule(device_rule.content) else "medium"
                )

                issues.append(
                    ComplianceIssue(
                        severity=severity,
                        rule_id=None,
                        rule_name=None,
                        issue_type="extra_rule",
                        description=f"Device has extra firewall rule not defined in policy: {device_rule.content}",
                        device="",
                        recommendation="Review if this rule is necessary or add it to the policy",
                        current_config=device_rule.content,
                        expected_config=None,
                    )
                )

        return issues

    def _is_docker_related_rule(self, rule_content: str) -> bool:
        """Check if a rule is Docker-related and should be ignored."""
        docker_indicators = [
            "docker",
            "br-",
            "DOCKER",
            "FORWARD",
            "PREROUTING",
            "POSTROUTING",
            "MASQUERADE",
            "conntrack",
            "addrtype",
            "DNAT",
            "SNAT",
        ]
        content_lower = rule_content.lower()
        return any(
            indicator.lower() in content_lower for indicator in docker_indicators
        )

    def _is_system_rule(self, rule_content: str) -> bool:
        """Check if a rule is a system-level rule (lower priority for compliance)."""
        system_indicators = [
            "localhost",
            "127.0.0.1",
            "::1",
            "lo interface",
            "loopback",
        ]
        content_lower = rule_content.lower()
        return any(indicator in content_lower for indicator in system_indicators)

    def _conflicts_with_policy(
        self, device_rule: ConfigurationItem, policy_rules: List[FirewallRule]
    ) -> bool:
        """Check if a Docker rule conflicts with explicit policy rules."""
        # This is a placeholder for more sophisticated conflict detection
        # For now, we assume Docker rules don't conflict with policy rules
        return False

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

        # Calculate overall compliance as average of device compliance percentages
        total_compliance = sum(
            device_result.compliance_percentage for device_result in device_results
        )
        overall_compliance = (total_compliance / len(devices)) if devices else 100

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

            # DEBUG: Print what we found on the device
            logger.debug("Device has %s configuration items", len(config_items))
            for item in config_items:
                logger.debug("Found %s: %s", item.type, item.content)

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

        # DEBUG: Print policy rules
        logger.debug("Policy has %s rules to check", total_rules)
        for rule in all_policy_rules:
            logger.debug("Policy rule: %s - %s", rule.name, rule)

        for rule in all_policy_rules:
            rule_issues = []

            if isinstance(rule, FirewallRule):
                rule_issues = self.rule_comparer.compare_firewall_rule(
                    rule, config_items
                )

                # DEBUG: Print comparison results
                logger.debug(
                    "Rule '%s' comparison found %s issues", rule.name, len(rule_issues)
                )
                for issue in rule_issues:
                    logger.debug("Issue: %s - %s", issue.issue_type, issue.description)
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
        self,
        audit_result: PolicyAuditResult,
        format: str = "text",
        full_report: bool = False,
    ) -> str:
        """Generate a human-readable audit report."""
        if format == "text":
            return self._generate_text_report(audit_result, full_report)
        elif format == "html":
            return self._generate_html_report(audit_result)
        elif format == "json":
            return audit_result.json(indent=2)
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def _generate_text_report(
        self, audit_result: PolicyAuditResult, full_report: bool = False
    ) -> str:
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
        medium_issues = audit_result.get_issues_by_severity("medium")
        low_issues = audit_result.get_issues_by_severity("low")

        report.append("ISSUE SUMMARY BY SEVERITY:")
        report.append(f"  Critical: {len(critical_issues)}")
        report.append(f"  High: {len(high_issues)}")
        report.append(f"  Medium: {len(medium_issues)}")
        report.append(f"  Low: {len(low_issues)}")
        report.append("")

        # Show detailed issues if full_report is enabled
        if full_report:
            report.append("DETAILED ISSUES BY SEVERITY:")
            report.append("=" * 80)

            # Critical Issues
            if critical_issues:
                report.append("")
                report.append("CRITICAL ISSUES:")
                report.append("-" * 40)
                for i, issue in enumerate(critical_issues, 1):
                    report.append(f"{i}. {issue.description}")
                    report.append(f"   Device: {issue.device}")
                    report.append(f"   Type: {issue.issue_type}")
                    if issue.rule_name:
                        report.append(f"   Rule: {issue.rule_name}")
                    report.append(f"   Recommendation: {issue.recommendation}")
                    if issue.current_config:
                        report.append(f"   Current Config: {issue.current_config}")
                    if issue.expected_config:
                        report.append("   Expected Config:")
                        formatted_config = self._format_firewall_rule(
                            issue.expected_config
                        )
                        for line in formatted_config.split("\n"):
                            report.append(f"     {line}")
                    report.append("")

            # High Issues
            if high_issues:
                report.append("")
                report.append("HIGH PRIORITY ISSUES:")
                report.append("-" * 40)
                for i, issue in enumerate(high_issues, 1):
                    report.append(f"{i}. {issue.description}")
                    report.append(f"   Device: {issue.device}")
                    report.append(f"   Type: {issue.issue_type}")
                    if issue.rule_name:
                        report.append(f"   Rule: {issue.rule_name}")
                    report.append(f"   Recommendation: {issue.recommendation}")
                    if issue.current_config:
                        report.append(f"   Current Config: {issue.current_config}")
                    if issue.expected_config:
                        report.append("   Expected Config:")
                        formatted_config = self._format_firewall_rule(
                            issue.expected_config
                        )
                        for line in formatted_config.split("\n"):
                            report.append(f"     {line}")
                    report.append("")

            # Medium Issues
            if medium_issues:
                report.append("")
                report.append("MEDIUM PRIORITY ISSUES:")
                report.append("-" * 40)
                for i, issue in enumerate(medium_issues, 1):
                    report.append(f"{i}. {issue.description}")
                    report.append(f"   Device: {issue.device}")
                    report.append(f"   Type: {issue.issue_type}")
                    if issue.rule_name:
                        report.append(f"   Rule: {issue.rule_name}")
                    report.append(f"   Recommendation: {issue.recommendation}")
                    if issue.current_config:
                        report.append(f"   Current Config: {issue.current_config}")
                    if issue.expected_config:
                        report.append("   Expected Config:")
                        formatted_config = self._format_firewall_rule(
                            issue.expected_config
                        )
                        for line in formatted_config.split("\n"):
                            report.append(f"     {line}")
                    report.append("")

            # Low Issues
            if low_issues:
                report.append("")
                report.append("LOW PRIORITY ISSUES:")
                report.append("-" * 40)
                for i, issue in enumerate(low_issues, 1):
                    report.append(f"{i}. {issue.description}")
                    report.append(f"   Device: {issue.device}")
                    report.append(f"   Type: {issue.issue_type}")
                    if issue.rule_name:
                        report.append(f"   Rule: {issue.rule_name}")
                    report.append(f"   Recommendation: {issue.recommendation}")
                    if issue.current_config:
                        report.append(f"   Current Config: {issue.current_config}")
                    if issue.expected_config:
                        report.append("   Expected Config:")
                        formatted_config = self._format_firewall_rule(
                            issue.expected_config
                        )
                        for line in formatted_config.split("\n"):
                            report.append(f"     {line}")
                    report.append("")

            report.append("=" * 80)
            report.append("")

        # Device details
        report.append("DEVICE AUDIT RESULTS:")
        report.append("-" * 40)

        for device_result in audit_result.device_results:
            report.append(f"Device: {device_result.device}")
            report.append(f"  Compliance: {device_result.compliance_percentage:.1f}%")
            report.append(f"  Issues: {len(device_result.issues)}")

            if device_result.issues and not full_report:
                # Show only critical and high issues in summary mode
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

    def _format_firewall_rule(self, rule) -> str:
        """Format a firewall rule for display in reports."""
        if not rule:
            return "N/A"

        # Import here to avoid circular imports
        from ..core.rules import FirewallRule

        if not isinstance(rule, FirewallRule):
            return str(rule)

        lines = []
        lines.append(f"Rule: {rule.name}")
        lines.append(f"    Description: {rule.description}")
        lines.append(f"    Action: {rule.action.value}")
        lines.append(f"    Direction: {rule.direction.value}")
        lines.append(f"    Protocol: {rule.protocol.name if rule.protocol else 'N/A'}")

        if rule.source_ips:
            source_ips = ", ".join([str(ip) for ip in rule.source_ips])
            lines.append(f"    Source IPs: {source_ips}")

        if rule.destination_ips:
            dest_ips = ", ".join([str(ip) for ip in rule.destination_ips])
            lines.append(f"    Destination IPs: {dest_ips}")

        if rule.source_ports:
            source_ports = ", ".join([str(port) for port in rule.source_ports])
            lines.append(f"    Source Ports: {source_ports}")

        if rule.destination_ports:
            dest_ports = ", ".join([str(port) for port in rule.destination_ports])
            lines.append(f"    Destination Ports: {dest_ports}")

        if rule.log_traffic:
            lines.append("    Logging: Enabled")

        lines.append(f"    Priority: {rule.priority}")

        return "\n".join(lines)
