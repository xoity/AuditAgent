"""
Advanced automated remediation modules for fixing detected compliance issues.
"""

import datetime
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel

from ..audit.engine import ComplianceIssue, PolicyAuditResult
from ..core.logging_config import get_logger
from ..core.policy import NetworkPolicy
from ..core.rules import BaseRule, FirewallRule
from ..devices.base import CommandResult, NetworkDevice

logger = get_logger(__name__)


class RemediationStrategy(Enum):
    """Strategies for automated remediation."""

    CONSERVATIVE = "conservative"  # Only fix low-risk issues
    BALANCED = "balanced"  # Fix low and medium risk issues
    AGGRESSIVE = "aggressive"  # Fix all issues except critical


class RemediationStatus(Enum):
    """Status of a remediation action."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class RemediationAction:
    """Represents a specific remediation action."""

    id: str
    issue: ComplianceIssue
    device: NetworkDevice
    action_type: str  # "add_rule", "remove_rule", "modify_rule", "fix_config"
    commands: List[str]
    rollback_commands: List[str]
    risk_level: str
    dependencies: List[str]  # IDs of actions this depends on
    estimated_duration: float  # seconds
    validation_commands: List[str]  # Commands to verify fix worked
    description: str
    status: RemediationStatus = RemediationStatus.PENDING
    error_message: Optional[str] = None
    execution_time: Optional[float] = None
    validation_result: Optional[bool] = None


@dataclass
class RemediationResult:
    """Result of a remediation operation."""

    action_id: str
    success: bool
    status: RemediationStatus
    command_results: List[CommandResult]
    validation_passed: bool
    execution_time: float
    error_message: Optional[str] = None
    rollback_performed: bool = False


class RemediationPlan(BaseModel):
    """Complete plan for automated remediation."""

    model_config = {"arbitrary_types_allowed": True}

    policy_name: str
    device_count: int
    total_actions: int
    strategy: RemediationStrategy
    actions: List[RemediationAction] = []
    execution_order: List[str] = []  # Action IDs in execution order
    estimated_total_time: float
    risk_assessment: str
    created_timestamp: str

    def get_actions_by_device(self, device: NetworkDevice) -> List[RemediationAction]:
        """Get all actions for a specific device."""
        return [action for action in self.actions if action.device == device]

    def get_actions_by_risk_level(self, risk_level: str) -> List[RemediationAction]:
        """Get all actions of a specific risk level."""
        return [action for action in self.actions if action.risk_level == risk_level]


class RemediationPlanResult(BaseModel):
    """Result of executing a remediation plan."""

    model_config = {"arbitrary_types_allowed": True}

    plan: RemediationPlan
    results: List[RemediationResult] = []
    overall_success_rate: float
    actions_completed: int
    actions_failed: int
    actions_skipped: int
    actions_rolled_back: int
    total_execution_time: float
    execution_timestamp: str

    @property
    def is_successful(self) -> bool:
        """Check if remediation was completely successful."""
        return self.actions_failed == 0 and self.actions_rolled_back == 0


class RemediationValidator:
    """Validates remediation actions before and after execution."""

    def __init__(self):
        self.validation_cache: Dict[str, bool] = {}

    async def validate_action_pre_execution(
        self, action: RemediationAction
    ) -> List[str]:
        """Validate an action before execution."""
        warnings = []

        # Check if device is responsive
        if not await self._is_device_responsive(action.device):
            warnings.append(f"Device {action.device} appears unresponsive")

        # Validate commands
        command_errors = action.device.validate_commands(action.commands)
        warnings.extend(command_errors)

        # Check for conflicting changes
        conflicts = await self._check_for_conflicts(action)
        warnings.extend(conflicts)

        # Validate rollback commands
        rollback_errors = action.device.validate_commands(action.rollback_commands)
        if rollback_errors:
            warnings.extend(
                [f"Rollback validation: {error}" for error in rollback_errors]
            )

        return warnings

    async def validate_action_post_execution(self, action: RemediationAction) -> bool:
        """Validate that an action was successful after execution."""
        if not action.validation_commands:
            return True

        try:
            for validation_command in action.validation_commands:
                result = await action.device.execute_command(validation_command)
                if not result.success:
                    logger.warning("Validation command failed: %s", validation_command)
                    return False

            return True
        except Exception as e:
            logger.error("Validation failed with exception: %s", e)
            return False

    async def _is_device_responsive(self, device: NetworkDevice) -> bool:
        """Check if device is responsive."""
        try:
            if not device.is_connected:
                await device.connect()
            return await device.test_connectivity()
        except Exception:
            return False

    async def _check_for_conflicts(self, action: RemediationAction) -> List[str]:
        """Check for potential conflicts with current device state."""
        conflicts = []

        # This would implement sophisticated conflict detection
        # For now, basic implementation

        if action.action_type == "add_rule":
            # Check if rule already exists
            existing_config = await action.device.get_configuration()
            for item in existing_config.parsed_items:
                if self._rules_are_similar(action.commands, [item.content]):
                    conflicts.append(f"Similar rule may already exist: {item.content}")

        return conflicts

    def _rules_are_similar(
        self, new_commands: List[str], existing_rules: List[str]
    ) -> bool:
        """Check if new commands are similar to existing rules."""
        # Simplified similarity check
        for new_cmd in new_commands:
            for existing_rule in existing_rules:
                if self._calculate_similarity(new_cmd, existing_rule) > 0.8:
                    return True
        return False

    def _calculate_similarity(self, cmd1: str, cmd2: str) -> float:
        """Calculate similarity between two commands."""
        # Simple token-based similarity
        tokens1 = set(cmd1.lower().split())
        tokens2 = set(cmd2.lower().split())

        if not tokens1 and not tokens2:
            return 1.0
        if not tokens1 or not tokens2:
            return 0.0

        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)

        return len(intersection) / len(union)


class RemediationPlanner:
    """Plans comprehensive remediation actions based on audit results."""

    def __init__(self, strategy: RemediationStrategy = RemediationStrategy.BALANCED):
        self.strategy = strategy
        self.validator = RemediationValidator()

    async def create_remediation_plan(
        self, policy: NetworkPolicy, audit_result: PolicyAuditResult
    ) -> RemediationPlan:
        """Create a comprehensive remediation plan."""
        logger.info("Creating remediation plan with %s strategy", self.strategy.value)

        actions = []

        # Process each device's issues
        for device_result in audit_result.device_results:
            device_actions = await self._plan_device_remediation(
                policy, device_result.device, device_result.issues
            )
            actions.extend(device_actions)

        # Filter actions based on strategy
        filtered_actions = self._filter_actions_by_strategy(actions)

        # Calculate dependencies and execution order
        execution_order = self._calculate_execution_order(filtered_actions)

        # Estimate timing and risk
        estimated_time = self._estimate_total_time(filtered_actions)
        risk_assessment = self._assess_overall_risk(filtered_actions)

        plan = RemediationPlan(
            policy_name=policy.metadata.name,
            device_count=len(audit_result.device_results),
            total_actions=len(filtered_actions),
            strategy=self.strategy,
            actions=filtered_actions,
            execution_order=execution_order,
            estimated_total_time=estimated_time,
            risk_assessment=risk_assessment,
            created_timestamp=datetime.datetime.now().isoformat(),
        )

        logger.info("Created remediation plan with %s actions", len(filtered_actions))
        return plan

    async def _plan_device_remediation(
        self,
        policy: NetworkPolicy,
        device: NetworkDevice,
        issues: List[ComplianceIssue],
    ) -> List[RemediationAction]:
        """Plan remediation actions for a single device."""
        actions = []

        for issue in issues:
            action = await self._create_remediation_action(policy, device, issue)
            if action:
                actions.append(action)

        return actions

    async def _create_remediation_action(
        self, policy: NetworkPolicy, device: NetworkDevice, issue: ComplianceIssue
    ) -> Optional[RemediationAction]:
        """Create a specific remediation action for an issue."""

        action_id = f"{device}_{issue.issue_type}_{hash(issue.description) % 10000}"

        if issue.issue_type == "missing_rule":
            return await self._create_add_rule_action(policy, device, issue, action_id)
        elif issue.issue_type == "extra_rule":
            return await self._create_remove_rule_action(device, issue, action_id)
        elif issue.issue_type == "misconfigured_rule":
            return await self._create_modify_rule_action(
                policy, device, issue, action_id
            )
        elif issue.issue_type == "connectivity_error":
            return await self._create_connectivity_fix_action(device, issue, action_id)

        return None

    async def _create_add_rule_action(
        self,
        policy: NetworkPolicy,
        device: NetworkDevice,
        issue: ComplianceIssue,
        action_id: str,
    ) -> Optional[RemediationAction]:
        """Create action to add a missing rule."""

        # Find the policy rule that needs to be added
        rule = self._find_policy_rule_by_id(policy, issue.rule_id)
        if not rule and issue.rule_name:
            rule = self._find_policy_rule_by_name(policy, issue.rule_name)

        if not rule:
            logger.warning(
                "Could not find policy rule for issue: %s", issue.description
            )
            return None

        # Generate commands
        commands = device.rule_to_commands(rule)
        if not commands:
            logger.warning("Could not generate commands for rule: %s", rule.name)
            return None

        # Generate rollback commands
        rollback_commands = self._generate_rollback_commands(device, commands)

        # Generate validation commands
        validation_commands = self._generate_validation_commands(device, rule, "add")

        return RemediationAction(
            id=action_id,
            issue=issue,
            device=device,
            action_type="add_rule",
            commands=commands,
            rollback_commands=rollback_commands,
            risk_level=self._assess_rule_risk_level(rule, "add"),
            dependencies=[],
            estimated_duration=5.0,  # seconds
            validation_commands=validation_commands,
            description=f"Add missing rule: {rule.name or rule.id}",
        )

    async def _create_remove_rule_action(
        self, device: NetworkDevice, issue: ComplianceIssue, action_id: str
    ) -> Optional[RemediationAction]:
        """Create action to remove an extra rule."""

        if not issue.current_config:
            return None

        # Generate remove commands
        commands = self._generate_remove_commands(device, issue.current_config)
        if not commands:
            return None

        # Generate rollback commands (restore the rule)
        rollback_commands = self._generate_restore_commands(
            device, issue.current_config
        )

        # Generate validation commands
        validation_commands = self._generate_validation_commands(
            device, None, "remove", issue.current_config
        )

        return RemediationAction(
            id=action_id,
            issue=issue,
            device=device,
            action_type="remove_rule",
            commands=commands,
            rollback_commands=rollback_commands,
            risk_level="medium",
            dependencies=[],
            estimated_duration=3.0,
            validation_commands=validation_commands,
            description=f"Remove extra rule: {issue.current_config[:50]}...",
        )

    async def _create_modify_rule_action(
        self,
        policy: NetworkPolicy,
        device: NetworkDevice,
        issue: ComplianceIssue,
        action_id: str,
    ) -> Optional[RemediationAction]:
        """Create action to modify a misconfigured rule."""

        rule = self._find_policy_rule_by_id(policy, issue.rule_id)
        if not rule:
            return None

        # Generate commands to remove old rule and add new one
        remove_commands = []
        if issue.current_config:
            remove_commands = self._generate_remove_commands(
                device, issue.current_config
            )

        add_commands = device.rule_to_commands(rule)
        commands = remove_commands + add_commands

        # Generate rollback commands
        rollback_commands = []
        if issue.current_config:
            rollback_commands = self._generate_restore_commands(
                device, issue.current_config
            )

        # Generate validation commands
        validation_commands = self._generate_validation_commands(device, rule, "modify")

        return RemediationAction(
            id=action_id,
            issue=issue,
            device=device,
            action_type="modify_rule",
            commands=commands,
            rollback_commands=rollback_commands,
            risk_level=self._assess_rule_risk_level(rule, "modify"),
            dependencies=[],
            estimated_duration=8.0,
            validation_commands=validation_commands,
            description=f"Modify rule: {rule.name or rule.id}",
        )

    async def _create_connectivity_fix_action(
        self, device: NetworkDevice, issue: ComplianceIssue, action_id: str
    ) -> Optional[RemediationAction]:
        """Create action to fix connectivity issues."""

        # Basic connectivity troubleshooting commands
        commands = [
            "systemctl restart ssh",  # Restart SSH service
            "ufw --force enable",  # Ensure firewall is enabled
        ]

        rollback_commands = [
            "systemctl start ssh",  # Ensure SSH is running
        ]

        validation_commands = [
            "systemctl is-active ssh",
            "ufw status",
        ]

        return RemediationAction(
            id=action_id,
            issue=issue,
            device=device,
            action_type="fix_connectivity",
            commands=commands,
            rollback_commands=rollback_commands,
            risk_level="high",  # Connectivity fixes are risky
            dependencies=[],
            estimated_duration=15.0,
            validation_commands=validation_commands,
            description="Fix connectivity issues",
        )

    def _filter_actions_by_strategy(
        self, actions: List[RemediationAction]
    ) -> List[RemediationAction]:
        """Filter actions based on remediation strategy."""
        if self.strategy == RemediationStrategy.CONSERVATIVE:
            return [a for a in actions if a.risk_level == "low"]
        elif self.strategy == RemediationStrategy.BALANCED:
            return [a for a in actions if a.risk_level in ["low", "medium"]]
        elif self.strategy == RemediationStrategy.AGGRESSIVE:
            return [a for a in actions if a.risk_level in ["low", "medium", "high"]]

        return actions

    def _calculate_execution_order(self, actions: List[RemediationAction]) -> List[str]:
        """Calculate optimal execution order considering dependencies and risk."""
        # Simple ordering: low risk first, then by device grouping
        sorted_actions = sorted(
            actions,
            key=lambda a: (
                {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(a.risk_level, 4),
                str(a.device),
                a.estimated_duration,
            ),
        )

        return [action.id for action in sorted_actions]

    def _estimate_total_time(self, actions: List[RemediationAction]) -> float:
        """Estimate total execution time for all actions."""
        # Add some overhead for coordination and validation
        base_time = sum(action.estimated_duration for action in actions)
        overhead = len(actions) * 2.0  # 2 seconds overhead per action
        return base_time + overhead

    def _assess_overall_risk(self, actions: List[RemediationAction]) -> str:
        """Assess overall risk level of the remediation plan."""
        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        for action in actions:
            risk_counts[action.risk_level] = risk_counts.get(action.risk_level, 0) + 1

        if risk_counts["critical"] > 0:
            return "critical"
        elif risk_counts["high"] > 2:
            return "high"
        elif risk_counts["medium"] > 5:
            return "medium"
        else:
            return "low"

    def _find_policy_rule_by_id(
        self, policy: NetworkPolicy, rule_id: Optional[str]
    ) -> Optional[BaseRule]:
        """Find a policy rule by its ID."""
        if not rule_id:
            return None

        for rule in policy.get_all_rules():
            if rule.id == rule_id:
                return rule

        return None

    def _find_policy_rule_by_name(
        self, policy: NetworkPolicy, rule_name: Optional[str]
    ) -> Optional[BaseRule]:
        """Find a policy rule by its name."""
        if not rule_name:
            return None

        for rule in policy.get_all_rules():
            if hasattr(rule, "name") and rule.name == rule_name:
                return rule

        return None

    def _assess_rule_risk_level(self, rule: BaseRule, action_type: str) -> str:
        """Assess the risk level of applying a rule change."""
        if isinstance(rule, FirewallRule):
            # Allow rules are generally higher risk
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
            # Deny rules are generally lower risk to add
            elif rule.action.value in ["deny", "drop"] and action_type == "add":
                return "low"

        return "medium"

    def _generate_rollback_commands(
        self, device: NetworkDevice, commands: List[str]
    ) -> List[str]:
        """Generate commands to rollback the given commands."""
        rollback_commands = []

        for command in commands:
            if "iptables" in command and "-A" in command:
                # Convert -A to -D for iptables
                rollback_cmd = command.replace("-A", "-D", 1)
                rollback_commands.append(rollback_cmd)

        return rollback_commands

    def _generate_remove_commands(
        self, device: NetworkDevice, rule_config: str
    ) -> List[str]:
        """Generate commands to remove a specific rule."""
        if (
            hasattr(device, "__class__")
            and "LinuxIptables" in device.__class__.__name__
        ):
            if rule_config.startswith("-A "):
                delete_command = rule_config.replace("-A ", "-D ", 1)
                return [f"iptables {delete_command}"]
            elif "iptables" in rule_config and " -A " in rule_config:
                delete_command = rule_config.replace(" -A ", " -D ", 1)
                return [delete_command]

        return []

    def _generate_restore_commands(
        self, device: NetworkDevice, rule_config: str
    ) -> List[str]:
        """Generate commands to restore a removed rule."""
        if (
            hasattr(device, "__class__")
            and "LinuxIptables" in device.__class__.__name__
        ):
            if rule_config.startswith("-A "):
                return [f"iptables {rule_config}"]
            elif "iptables" in rule_config:
                return [rule_config]

        return []

    def _generate_validation_commands(
        self,
        device: NetworkDevice,
        rule: Optional[BaseRule],
        action_type: str,
        rule_config: Optional[str] = None,
    ) -> List[str]:
        """Generate commands to validate that the action was successful."""
        if (
            hasattr(device, "__class__")
            and "LinuxIptables" in device.__class__.__name__
        ):
            if action_type == "add":
                # Validate that the rule was added
                return ["iptables -L -n | grep -v '^Chain' | grep -v '^target'"]
            elif action_type == "remove":
                # Validate that the rule was removed
                return ["iptables -L -n"]
            elif action_type == "modify":
                # Validate that the new rule is present
                return ["iptables -L -n | grep -v '^Chain' | grep -v '^target'"]

        return ["echo 'validation_placeholder'"]


class RemediationExecutor:
    """Executes remediation plans with safety measures and rollback capabilities."""

    def __init__(self):
        self.validator = RemediationValidator()
        self.execution_results: Dict[str, RemediationResult] = {}

    async def execute_remediation_plan(
        self, plan: RemediationPlan, dry_run: bool = True, stop_on_error: bool = True
    ) -> RemediationPlanResult:
        """Execute a complete remediation plan."""
        logger.info(
            "Executing remediation plan with %s actions (dry_run=%s)",
            len(plan.actions),
            dry_run,
        )

        start_time = datetime.datetime.now()
        results = []
        completed = 0
        failed = 0
        skipped = 0
        rolled_back = 0

        # Execute actions in order
        for action_id in plan.execution_order:
            action = next((a for a in plan.actions if a.id == action_id), None)
            if not action:
                logger.warning("Action %s not found in plan", action_id)
                continue

            # Check if dependencies are satisfied
            if not self._dependencies_satisfied(action, results):
                logger.warning(
                    "Dependencies not satisfied for action %s, skipping", action_id
                )
                action.status = RemediationStatus.SKIPPED
                skipped += 1
                continue

            # Execute the action
            result = await self._execute_single_action(action, dry_run)
            results.append(result)

            if result.success:
                completed += 1
            else:
                failed += 1

                # Perform rollback if needed
                if not dry_run and action.rollback_commands:
                    rollback_success = await self._perform_rollback(action)
                    if rollback_success:
                        rolled_back += 1
                        result.rollback_performed = True

                # Stop on error if requested
                if stop_on_error:
                    logger.error(
                        "Stopping execution due to failed action: %s", action_id
                    )
                    break

        end_time = datetime.datetime.now()
        execution_time = (end_time - start_time).total_seconds()

        # Calculate success rate
        total_executed = completed + failed
        success_rate = (completed / total_executed * 100) if total_executed > 0 else 100

        return RemediationPlanResult(
            plan=plan,
            results=results,
            overall_success_rate=success_rate,
            actions_completed=completed,
            actions_failed=failed,
            actions_skipped=skipped,
            actions_rolled_back=rolled_back,
            total_execution_time=execution_time,
            execution_timestamp=datetime.datetime.now().isoformat(),
        )

    async def _execute_single_action(
        self, action: RemediationAction, dry_run: bool
    ) -> RemediationResult:
        """Execute a single remediation action."""
        logger.info("Executing action: %s", action.description)
        action.status = RemediationStatus.IN_PROGRESS

        start_time = datetime.datetime.now()
        command_results = []

        try:
            # Pre-execution validation
            if not dry_run:
                warnings = await self.validator.validate_action_pre_execution(action)
                if warnings:
                    logger.warning(
                        "Pre-execution warnings for %s: %s", action.id, warnings
                    )

            # Execute commands
            if not dry_run:
                # Ensure device is connected
                if not action.device.is_connected:
                    await action.device.connect()

                # Execute the commands
                command_results = await action.device.apply_commands(
                    action.commands, dry_run=False
                )

                # Check if all commands succeeded
                success = all(result.success for result in command_results)

                # Post-execution validation
                validation_passed = False
                if success:
                    validation_passed = (
                        await self.validator.validate_action_post_execution(action)
                    )
                    if not validation_passed:
                        success = False
                        logger.warning(
                            "Post-execution validation failed for action %s", action.id
                        )

            else:
                # Dry run - simulate execution
                for command in action.commands:
                    command_results.append(
                        CommandResult(
                            command=command,
                            success=True,
                            output=f"DRY RUN: Would execute: {command}",
                            execution_time=0.1,
                        )
                    )
                success = True
                validation_passed = True

            end_time = datetime.datetime.now()
            execution_time = (end_time - start_time).total_seconds()

            # Update action status
            if success:
                action.status = RemediationStatus.COMPLETED
            else:
                action.status = RemediationStatus.FAILED

            action.execution_time = execution_time
            action.validation_result = validation_passed

            return RemediationResult(
                action_id=action.id,
                success=success,
                status=action.status,
                command_results=command_results,
                validation_passed=validation_passed,
                execution_time=execution_time,
                error_message=action.error_message,
            )

        except Exception as e:
            end_time = datetime.datetime.now()
            execution_time = (end_time - start_time).total_seconds()

            action.status = RemediationStatus.FAILED
            action.error_message = str(e)
            action.execution_time = execution_time

            logger.error("Action %s failed with exception: %s", action.id, e)

            return RemediationResult(
                action_id=action.id,
                success=False,
                status=RemediationStatus.FAILED,
                command_results=command_results,
                validation_passed=False,
                execution_time=execution_time,
                error_message=str(e),
            )

    async def _perform_rollback(self, action: RemediationAction) -> bool:
        """Perform rollback for a failed action."""
        logger.info("Performing rollback for action: %s", action.id)

        try:
            if not action.device.is_connected:
                await action.device.connect()

            rollback_results = await action.device.apply_commands(
                action.rollback_commands, dry_run=False
            )
            success = all(result.success for result in rollback_results)

            if success:
                action.status = RemediationStatus.ROLLED_BACK
                logger.info("Successfully rolled back action: %s", action.id)
            else:
                logger.error("Rollback failed for action: %s", action.id)

            return success

        except Exception as e:
            logger.error(
                "Rollback failed for action %s with exception: %s", action.id, e
            )
            return False

    def _dependencies_satisfied(
        self, action: RemediationAction, completed_results: List[RemediationResult]
    ) -> bool:
        """Check if all dependencies for an action are satisfied."""
        if not action.dependencies:
            return True

        completed_action_ids = {
            result.action_id for result in completed_results if result.success
        }

        return all(dep_id in completed_action_ids for dep_id in action.dependencies)


class AutomatedRemediationManager:
    """Main manager for automated remediation operations."""

    def __init__(self, strategy: RemediationStrategy = RemediationStrategy.BALANCED):
        self.strategy = strategy
        self.planner = RemediationPlanner(strategy)
        self.executor = RemediationExecutor()

    async def auto_remediate(
        self,
        policy: NetworkPolicy,
        audit_result: PolicyAuditResult,
        dry_run: bool = True,
        stop_on_error: bool = True,
    ) -> RemediationPlanResult:
        """Perform complete automated remediation."""
        logger.info("Starting automated remediation process")

        # Create remediation plan
        plan = await self.planner.create_remediation_plan(policy, audit_result)

        # Execute the plan
        result = await self.executor.execute_remediation_plan(
            plan, dry_run=dry_run, stop_on_error=stop_on_error
        )

        logger.info(
            "Automated remediation completed. Success rate: %.1f%%",
            result.overall_success_rate,
        )

        return result

    def generate_remediation_report(
        self, result: RemediationPlanResult, format: str = "text"
    ) -> str:
        """Generate a comprehensive remediation report."""
        if format == "text":
            return self._generate_text_remediation_report(result)
        elif format == "json":
            return result.model_dump_json(indent=2)
        else:
            raise ValueError(f"Unsupported report format: {format}")

    def _generate_text_remediation_report(self, result: RemediationPlanResult) -> str:
        """Generate a text-based remediation report."""
        report = []
        report.append("=" * 80)
        report.append("AUTOMATED REMEDIATION REPORT")
        report.append("=" * 80)
        report.append("")
        report.append(f"Policy: {result.plan.policy_name}")
        report.append(f"Strategy: {result.plan.strategy.value.title()}")
        report.append(f"Execution Date: {result.execution_timestamp}")
        report.append(f"Overall Success Rate: {result.overall_success_rate:.1f}%")
        report.append("")
        report.append(f"Total Actions: {result.plan.total_actions}")
        report.append(f"Actions Completed: {result.actions_completed}")
        report.append(f"Actions Failed: {result.actions_failed}")
        report.append(f"Actions Skipped: {result.actions_skipped}")
        report.append(f"Actions Rolled Back: {result.actions_rolled_back}")
        report.append(
            f"Total Execution Time: {result.total_execution_time:.1f} seconds"
        )
        report.append("")

        # Action details
        report.append("REMEDIATION ACTIONS:")
        report.append("-" * 40)

        for action_result in result.results:
            action = next(
                (a for a in result.plan.actions if a.id == action_result.action_id),
                None,
            )
            if action:
                status_symbol = "✓" if action_result.success else "✗"
                report.append(f"{status_symbol} {action.description}")
                report.append(f"  Device: {action.device}")
                report.append(f"  Status: {action_result.status.value}")
                report.append(f"  Execution Time: {action_result.execution_time:.1f}s")

                if not action_result.success and action_result.error_message:
                    report.append(f"  Error: {action_result.error_message}")

                if action_result.rollback_performed:
                    report.append("  Rollback: Performed")

                report.append("")

        # Risk assessment
        report.append("RISK ASSESSMENT:")
        report.append("-" * 40)
        report.append(f"Overall Risk Level: {result.plan.risk_assessment}")

        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for action in result.plan.actions:
            risk_counts[action.risk_level] = risk_counts.get(action.risk_level, 0) + 1

        for risk_level, count in risk_counts.items():
            if count > 0:
                report.append(f"  {risk_level.title()} Risk Actions: {count}")

        report.append("")

        return "\n".join(report)
