"""
Enforcement engine for applying policy changes to network devices.
"""

import datetime
from dataclasses import dataclass
from typing import List, Optional

from pydantic import BaseModel

from ..audit.engine import AuditEngine, ComplianceIssue, PolicyAuditResult
from ..core.logging_config import get_logger
from ..core.policy import NetworkPolicy
from ..core.rules import BaseRule, FirewallRule
from ..devices.base import CommandResult, NetworkDevice

logger = get_logger(__name__)


@dataclass
class EnforcementAction:
    """Represents an action to be taken during enforcement."""

    device: NetworkDevice
    rule: BaseRule
    action_type: str  # "add", "modify", "remove"
    commands: List[str]
    description: str
    risk_level: str  # "low", "medium", "high", "critical"


@dataclass
class DeviceEnforcementResult:
    """Results of enforcement on a single device."""

    device: NetworkDevice
    actions_planned: int
    actions_executed: int
    actions_successful: int
    actions_failed: int
    command_results: List[CommandResult]
    enforcement_timestamp: str

    @property
    def success_rate(self) -> float:
        """Calculate the success rate of enforcement actions."""
        if self.actions_executed == 0:
            return 100.0
        return (self.actions_successful / self.actions_executed) * 100


class PolicyEnforcementResult(BaseModel):
    """Complete enforcement results for a policy across multiple devices."""

    model_config = {"arbitrary_types_allowed": True}

    policy_name: str
    devices_processed: int
    total_actions_planned: int
    total_actions_executed: int
    total_actions_successful: int
    total_actions_failed: int
    device_results: List[DeviceEnforcementResult] = []
    overall_success_rate: float
    enforcement_timestamp: str
    dry_run: bool

    @property
    def is_successful(self) -> bool:
        """Check if enforcement was completely successful."""
        return self.total_actions_failed == 0


class PreflightValidator:
    """Validates changes before applying them to devices."""

    def __init__(self):
        pass

    def validate_enforcement_actions(
        self, actions: List[EnforcementAction]
    ) -> List[str]:
        """Validate a list of enforcement actions."""
        warnings = []

        for action in actions:
            # Validate individual action
            action_warnings = self.validate_action(action)
            warnings.extend(action_warnings)

        # Check for conflicts between actions
        conflict_warnings = self.check_action_conflicts(actions)
        warnings.extend(conflict_warnings)

        return warnings

    def validate_action(self, action: EnforcementAction) -> List[str]:
        """Validate a single enforcement action."""
        warnings = []

        # Check command syntax
        command_errors = action.device.validate_commands(action.commands)
        if command_errors:
            warnings.extend(
                [f"Command validation error: {error}" for error in command_errors]
            )

        # Check risk level
        if action.risk_level in ["high", "critical"]:
            warnings.append(f"High-risk action: {action.description}")

        # Check for potentially disruptive commands
        for command in action.commands:
            if self.is_potentially_disruptive(command):
                warnings.append(f"Potentially disruptive command: {command}")

        return warnings

    def is_potentially_disruptive(self, command: str) -> bool:
        """Check if a command is potentially disruptive."""
        disruptive_patterns = [
            "shutdown",
            "no ip route",
            "clear",
            "reload",
            "erase",
            "delete",
            "access-list.*deny.*any any",
        ]

        import re

        command_lower = command.lower()

        for pattern in disruptive_patterns:
            if re.search(pattern, command_lower):
                return True

        return False

    def check_action_conflicts(self, actions: List[EnforcementAction]) -> List[str]:
        """Check for conflicts between multiple actions."""
        warnings = []

        # Group actions by device
        device_actions = {}
        for action in actions:
            device_key = str(action.device)
            if device_key not in device_actions:
                device_actions[device_key] = []
            device_actions[device_key].append(action)

        # Check for conflicts within each device
        for device_key, dev_actions in device_actions.items():
            conflicts = self.find_action_conflicts(dev_actions)
            warnings.extend(conflicts)

        return warnings

    def find_action_conflicts(self, actions: List[EnforcementAction]) -> List[str]:
        """Find conflicts between actions on the same device."""
        conflicts = []

        # Check for add/remove conflicts
        add_actions = [a for a in actions if a.action_type == "add"]
        remove_actions = [a for a in actions if a.action_type == "remove"]

        for add_action in add_actions:
            for remove_action in remove_actions:
                if self.actions_conflict(add_action, remove_action):
                    conflicts.append(
                        f"Conflict: Adding rule '{add_action.description}' while removing '{remove_action.description}'"
                    )

        return conflicts

    def actions_conflict(
        self, action1: EnforcementAction, action2: EnforcementAction
    ) -> bool:
        """Check if two actions conflict with each other."""
        # Simplified conflict detection
        # In practice, this would need more sophisticated logic

        if action1.rule.id and action2.rule.id:
            return action1.rule.id == action2.rule.id

        return False


class EnforcementPlanner:
    """Plans enforcement actions based on audit results."""

    def __init__(self):
        pass

    def plan_enforcement(
        self, policy: NetworkPolicy, audit_result: PolicyAuditResult
    ) -> List[EnforcementAction]:
        """Plan enforcement actions based on audit results."""
        actions = []

        for device_result in audit_result.device_results:
            device_actions = self.plan_device_enforcement(policy, device_result)
            actions.extend(device_actions)

        return actions

    def plan_device_enforcement(
        self, policy: NetworkPolicy, device_result
    ) -> List[EnforcementAction]:
        """Plan enforcement actions for a single device."""
        actions = []

        for issue in device_result.issues:
            action = self.create_action_for_issue(policy, device_result.device, issue)
            if action:
                actions.append(action)

        return actions

    def create_action_for_issue(
        self, policy: NetworkPolicy, device: NetworkDevice, issue: ComplianceIssue
    ) -> Optional[EnforcementAction]:
        """Create an enforcement action for a specific compliance issue."""

        logger.debug(
            f"Creating action for issue: {issue.issue_type} - {issue.description}"
        )

        if issue.issue_type == "missing_rule":
            action = self.create_add_rule_action(policy, device, issue)
            logger.debug(f"Created add action: {action is not None}")
            return action
        elif issue.issue_type == "extra_rule":
            return self.create_remove_rule_action(device, issue)
        elif issue.issue_type == "misconfigured_rule":
            return self.create_modify_rule_action(policy, device, issue)

        return None

    def create_add_rule_action(
        self, policy: NetworkPolicy, device: NetworkDevice, issue: ComplianceIssue
    ) -> Optional[EnforcementAction]:
        """Create an action to add a missing rule."""

        # Find the policy rule that's missing
        logger.debug(
            f"Looking for rule with ID: {issue.rule_id}, name: {issue.rule_name}"
        )
        rule = self.find_policy_rule_by_id(policy, issue.rule_id)
        if not rule and issue.rule_name:
            logger.debug("ID lookup failed, trying name lookup")
            rule = self.find_policy_rule_by_name(policy, issue.rule_name)
        logger.debug(f"Found rule: {rule is not None}")
        if not rule:
            logger.debug("Rule not found, returning None")
            return None

        # Generate device commands for the rule
        logger.debug("Generating commands for rule")
        logger.debug(f"Rule type: {type(rule).__name__}")
        logger.debug(
            f"Rule name/id: {getattr(rule, 'name', getattr(rule, 'id', 'unknown'))}"
        )
        if hasattr(rule, "__dict__"):
            logger.debug(f"Rule dict: {rule.__dict__}")

        commands = device.rule_to_commands(rule)

        logger.debug(f"Generated commands: {commands}")
        if not commands:
            logger.debug("No commands generated, returning None")
            return None

        return EnforcementAction(
            device=device,
            rule=rule,
            action_type="add",
            commands=commands,
            description=f"Add missing rule: {rule.name or rule.id}",
            risk_level=self.assess_risk_level(rule, "add"),
        )

    def create_remove_rule_action(
        self, device: NetworkDevice, issue: ComplianceIssue
    ) -> Optional[EnforcementAction]:
        """Create an action to remove an extra rule."""

        if not issue.current_config:
            return None

        # Generate commands to remove the rule
        # This is device-specific and would need implementation per device type
        commands = self.generate_remove_commands(device, issue.current_config)

        # Create a dummy rule for tracking
        from ..core.rules import FirewallRule

        dummy_rule = FirewallRule(
            name="extra_rule", description="Extra rule to be removed"
        )

        return EnforcementAction(
            device=device,
            rule=dummy_rule,
            action_type="remove",
            commands=commands,
            description=f"Remove extra rule: {issue.current_config}",
            risk_level="medium",
        )

    def create_modify_rule_action(
        self, policy: NetworkPolicy, device: NetworkDevice, issue: ComplianceIssue
    ) -> Optional[EnforcementAction]:
        """Create an action to modify a misconfigured rule."""

        rule = self.find_policy_rule_by_id(policy, issue.rule_id)
        if not rule or not issue.expected_config:
            return None

        # Generate commands to modify the rule
        # This might involve removing the old rule and adding the new one
        remove_commands = self.generate_remove_commands(
            device, issue.current_config or ""
        )
        add_commands = device.rule_to_commands(rule)

        commands = remove_commands + add_commands

        return EnforcementAction(
            device=device,
            rule=rule,
            action_type="modify",
            commands=commands,
            description=f"Modify rule: {rule.name or rule.id}",
            risk_level=self.assess_risk_level(rule, "modify"),
        )

    def find_policy_rule_by_id(
        self, policy: NetworkPolicy, rule_id: Optional[str]
    ) -> Optional[BaseRule]:
        """Find a policy rule by its ID."""
        if not rule_id:
            return None

        for rule in policy.get_all_rules():
            if rule.id == rule_id:
                return rule

        return None

    def find_policy_rule_by_name(
        self, policy: NetworkPolicy, rule_name: Optional[str]
    ) -> Optional[BaseRule]:
        """Find a policy rule by its name."""
        if not rule_name:
            return None

        for rule in policy.get_all_rules():
            if hasattr(rule, "name") and rule.name == rule_name:
                return rule

        return None

    def generate_remove_commands(
        self, device: NetworkDevice, rule_config: str
    ) -> List[str]:
        """Generate commands to remove a rule (device-specific)."""
        logger.debug("Generating remove commands")
        logger.debug(f"Device type: {type(device).__name__}")
        logger.debug(f"Rule config: {rule_config}")

        # Handle iptables rules
        if (
            hasattr(device, "__class__")
            and "LinuxIptables" in device.__class__.__name__
        ):
            # Convert iptables -A (append) rule to -D (delete) rule
            if rule_config.startswith("-A "):
                # Replace -A with -D to delete the rule
                delete_command = rule_config.replace("-A ", "-D ", 1)
                # Remove line numbers and rule numbering if present
                import re

                delete_command = re.sub(r"\s+\d+\s+", " ", delete_command)
                delete_command = f"iptables {delete_command}"
                logger.debug(f"Generated iptables delete command: {delete_command}")
                return [delete_command]

            # Handle other iptables rule formats
            elif "iptables" in rule_config:
                # If it's already a full iptables command, convert to delete
                if " -A " in rule_config:
                    delete_command = rule_config.replace(" -A ", " -D ", 1)
                    logger.debug(f"Generated iptables delete command: {delete_command}")
                    return [delete_command]
                else:
                    logger.debug(f"Cannot generate delete command for: {rule_config}")
                    return []
            else:
                logger.debug(f"Unknown iptables rule format: {rule_config}")
                return []

        # Handle Cisco-style rules
        elif "access-list" in rule_config:
            # For Cisco devices, use "no" prefix
            command = f"no {rule_config}"
            logger.debug(f"Generated Cisco delete command: {command}")
            return [command]

        logger.debug("No matching rule format found")
        return []

    def assess_risk_level(self, rule: BaseRule, action_type: str) -> str:
        """Assess the risk level of applying a rule change."""

        if isinstance(rule, FirewallRule):
            # Deny rules are generally lower risk to add
            if rule.action.value in ["deny", "drop"] and action_type == "add":
                return "low"

            # Allow rules are higher risk
            if rule.action.value == "allow":
                # Check if it's overly permissive
                if (
                    rule.source_ips
                    and any(str(ip) == "0.0.0.0/0" for ip in rule.source_ips)
                    and rule.destination_ips
                    and any(str(ip) == "0.0.0.0/0" for ip in rule.destination_ips)
                ):
                    return "high"
                else:
                    return "medium"

        return "medium"


class EnforcementEngine:
    """Main enforcement engine for applying policy changes."""

    def __init__(self):
        self.audit_engine = AuditEngine()
        self.planner = EnforcementPlanner()
        self.validator = PreflightValidator()

    async def enforce_policy(
        self, policy: NetworkPolicy, devices: List[NetworkDevice], dry_run: bool = False
    ) -> PolicyEnforcementResult:
        """Enforce a policy on multiple devices."""

        # First, audit the current state
        audit_result = await self.audit_engine.audit_policy(policy, devices)

        # Plan enforcement actions
        actions = self.planner.plan_enforcement(policy, audit_result)

        # Validate actions
        validation_warnings = self.validator.validate_enforcement_actions(actions)
        if validation_warnings and not dry_run:
            logger.warning("Validation warnings found:")
            for warning in validation_warnings:
                logger.warning(f"  - {warning}")

        # Execute actions
        device_results = []
        total_actions_planned = len(actions)
        total_actions_executed = 0
        total_actions_successful = 0
        total_actions_failed = 0

        # Group actions by device
        device_actions = {}
        for action in actions:
            device_key = str(action.device)
            if device_key not in device_actions:
                device_actions[device_key] = []
            device_actions[device_key].append(action)

        for device in devices:
            device_key = str(device)
            dev_actions = device_actions.get(device_key, [])

            device_result = await self.enforce_device(device, dev_actions, dry_run)
            device_results.append(device_result)

            total_actions_executed += device_result.actions_executed
            total_actions_successful += device_result.actions_successful
            total_actions_failed += device_result.actions_failed

        # Calculate overall success rate
        overall_success_rate = (
            (total_actions_successful / total_actions_executed * 100)
            if total_actions_executed > 0
            else 100
        )

        return PolicyEnforcementResult(
            policy_name=policy.metadata.name,
            devices_processed=len(devices),
            total_actions_planned=total_actions_planned,
            total_actions_executed=total_actions_executed,
            total_actions_successful=total_actions_successful,
            total_actions_failed=total_actions_failed,
            device_results=device_results,
            overall_success_rate=overall_success_rate,
            enforcement_timestamp=datetime.datetime.now().isoformat(),
            dry_run=dry_run,
        )

    async def enforce_device(
        self,
        device: NetworkDevice,
        actions: List[EnforcementAction],
        dry_run: bool = False,
    ) -> DeviceEnforcementResult:
        """Enforce actions on a single device."""

        command_results = []
        actions_executed = 0
        actions_successful = 0
        actions_failed = 0

        if not dry_run:
            # Ensure device is connected
            if not device.is_connected:
                await device.connect()

        # Execute actions in order
        logger.debug(f"Processing {len(actions)} actions")
        for i, action in enumerate(actions):
            logger.debug(f"Action {i + 1}: {action.action_type} - {action.description}")
            logger.debug(f"Commands: {action.commands}")
            logger.debug(f"Command count: {len(action.commands)}")

            if not dry_run:
                # Execute the action
                results = await device.apply_commands(action.commands, dry_run=False)
                command_results.extend(results)

                # Check if action was successful
                action_successful = all(result.success for result in results)

                actions_executed += 1
                if action_successful:
                    actions_successful += 1
                else:
                    actions_failed += 1
            else:
                # Dry run - simulate the action
                for command in action.commands:
                    command_results.append(
                        CommandResult(
                            command=command,
                            success=True,
                            output=f"DRY RUN: Would execute: {command}",
                            execution_time=0.0,
                        )
                    )

                actions_executed += 1
                actions_successful += 1

        return DeviceEnforcementResult(
            device=device,
            actions_planned=len(actions),
            actions_executed=actions_executed,
            actions_successful=actions_successful,
            actions_failed=actions_failed,
            command_results=command_results,
            enforcement_timestamp=datetime.datetime.now().isoformat(),
        )

    def generate_enforcement_report(
        self, enforcement_result: PolicyEnforcementResult, format: str = "text"
    ) -> str:
        """Generate a human-readable enforcement report."""
        if format == "text":
            return self._generate_text_enforcement_report(enforcement_result)
        elif format == "json":
            return enforcement_result.json(indent=2)
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def _generate_text_enforcement_report(self, result: PolicyEnforcementResult) -> str:
        """Generate a text-based enforcement report."""
        report = []
        report.append("=" * 80)
        report.append("NETWORK SECURITY POLICY ENFORCEMENT REPORT")
        report.append("=" * 80)
        report.append("")
        report.append(f"Policy: {result.policy_name}")
        report.append(f"Enforcement Date: {result.enforcement_timestamp}")
        report.append(f"Mode: {'DRY RUN' if result.dry_run else 'LIVE ENFORCEMENT'}")
        report.append(f"Overall Success Rate: {result.overall_success_rate:.1f}%")
        report.append("")
        report.append(f"Devices Processed: {result.devices_processed}")
        report.append(f"Total Actions Planned: {result.total_actions_planned}")
        report.append(f"Total Actions Executed: {result.total_actions_executed}")
        report.append(f"Successful Actions: {result.total_actions_successful}")
        report.append(f"Failed Actions: {result.total_actions_failed}")
        report.append("")

        # Device details
        report.append("DEVICE ENFORCEMENT RESULTS:")
        report.append("-" * 40)

        for device_result in result.device_results:
            report.append(f"Device: {device_result.device}")
            report.append(f"  Success Rate: {device_result.success_rate:.1f}%")
            report.append(f"  Actions Executed: {device_result.actions_executed}")
            report.append(f"  Successful: {device_result.actions_successful}")
            report.append(f"  Failed: {device_result.actions_failed}")

            if device_result.actions_failed > 0:
                report.append("  Failed Commands:")
                for cmd_result in device_result.command_results:
                    if not cmd_result.success:
                        report.append(f"    - {cmd_result.command}: {cmd_result.error}")

            report.append("")

        return "\n".join(report)
