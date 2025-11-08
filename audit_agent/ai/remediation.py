"""
AI-powered remediation engine.
"""

import asyncio
from pathlib import Path
from typing import Optional

import yaml

from ..audit.engine import AuditEngine, PolicyAuditResult
from ..core.logging_config import get_logger
from ..core.policy import NetworkPolicy
from ..core.rules import FirewallRule
from .analyzer import AuditResultAnalyzer
from .config import AIConfig, AIProvider
from .providers import get_provider

logger = get_logger(__name__)


class AIRemediationEngine:
    """Engine for AI-powered policy remediation."""

    def __init__(self, config: Optional[AIConfig] = None):
        """Initialize the AI remediation engine."""
        self.config = config or AIConfig.load_from_file()
        self.analyzer = AuditResultAnalyzer()
        self.audit_engine = AuditEngine()

    def generate_remediation_policy(
        self,
        audit_result: PolicyAuditResult,
        original_policy: NetworkPolicy,
        provider: Optional[AIProvider] = None,
        temperature: float = 0.3,
    ) -> str:
        """
        Generate a remediation policy using AI.

        Args:
            audit_result: The audit result containing compliance issues
            original_policy: The original policy that was audited
            provider: AI provider to use (defaults to config default)
            temperature: AI temperature for generation (lower = more deterministic)

        Returns:
            YAML string containing the remediation policy
        """
        logger.info(f"Generating AI remediation policy for {audit_result.policy_name}")

        # Analyze audit results
        analysis = self.analyzer.analyze(audit_result)
        logger.debug(
            f"Analyzed {analysis['total_issues']} issues across {len(analysis['devices'])} devices"
        )

        # Convert original policy to YAML using proper serialization
        # Use model_dump with mode='json' to ensure enums are serialized as strings
        original_yaml = yaml.safe_dump(
            original_policy.model_dump(mode='json'), 
            default_flow_style=False, 
            sort_keys=False,
            allow_unicode=True
        )

        # Generate remediation request
        prompt = self.analyzer.generate_remediation_request(analysis, original_yaml)

        # Get AI provider and generate policy
        ai_provider = get_provider(self.config, provider)

        system_prompt = """You are an expert network security engineer specializing in firewall policy compliance.
Your task is to generate corrected firewall policies that achieve 100% compliance.
You understand iptables, network security best practices, and YAML policy formats.
Always generate valid, complete YAML policies."""

        logger.info(f"Calling AI provider: {ai_provider.__class__.__name__}")
        remediation_yaml = ai_provider.generate_text(
            prompt, system_prompt=system_prompt, temperature=temperature
        )

        # Clean up response
        remediation_yaml = self._clean_yaml_response(remediation_yaml)

        # Validate it's valid YAML
        try:
            yaml.safe_load(remediation_yaml)
            logger.info("Generated valid YAML policy")
        except yaml.YAMLError as e:
            logger.error(f"Generated invalid YAML: {e}")
            raise ValueError(f"AI generated invalid YAML: {e}") from e

        return remediation_yaml

    def _clean_yaml_response(self, response: str) -> str:
        """Clean up AI response to extract pure YAML."""
        response = response.strip()

        # Remove markdown code blocks
        if response.startswith("```yaml"):
            response = response[7:]
        elif response.startswith("```"):
            response = response[3:]

        if response.endswith("```"):
            response = response[:-3]

        response = response.strip()
        return response

    def generate_and_validate(
        self,
        audit_result: PolicyAuditResult,
        original_policy: NetworkPolicy,
        devices: list,
        provider: Optional[AIProvider] = None,
        max_iterations: int = 3,
    ) -> tuple[str, PolicyAuditResult]:
        """
        Generate remediation policy and validate it achieves better compliance.

        Args:
            audit_result: Initial audit result
            original_policy: Original policy
            devices: List of devices to audit against
            provider: AI provider to use
            max_iterations: Maximum number of remediation attempts

        Returns:
            Tuple of (remediation_yaml, final_audit_result)
        """
        # Check if all issues are missing_rule - this means device is non-compliant, not policy
        all_missing = all(
            issue.issue_type == "missing_rule"
            for device_result in audit_result.device_results
            for issue in device_result.issues
        )
        
        if all_missing and audit_result.total_issues > 0:
            logger.warning(
                "All compliance issues are 'missing_rule' - this means the device lacks "
                "the rules defined in the policy. The policy itself appears correct."
            )
            logger.info(
                "Returning original policy as remediation. You should ENFORCE this policy "
                "on the device to achieve compliance."
            )
            # Return the original policy as YAML
            original_yaml = original_policy.export_to_yaml()
            return original_yaml, audit_result
        
        best_yaml = None
        best_result = audit_result
        best_compliance = audit_result.overall_compliance_percentage

        for iteration in range(max_iterations):
            logger.info(
                f"Remediation iteration {iteration + 1}/{max_iterations} "
                f"(current compliance: {best_compliance:.1f}%)"
            )

            # Generate remediation policy
            remediation_yaml = self.generate_remediation_policy(
                best_result, original_policy, provider=provider
            )

            # Parse and validate
            try:
                remediation_policy = NetworkPolicy.from_yaml(remediation_yaml)
            except Exception as e:
                logger.warning(f"Failed to parse generated policy: {e}")
                # Show first 1000 chars to diagnose the issue
                preview = remediation_yaml[:1000] if len(remediation_yaml) > 1000 else remediation_yaml
                logger.warning(f"Generated YAML content:\n{preview}")
                if iteration == max_iterations - 1:
                    if best_yaml:
                        return best_yaml, best_result
                    # If we never got a valid policy, raise the error
                    raise
                continue

            # Audit the remediation policy
            try:
                new_audit_result = asyncio.run(
                    self.audit_engine.audit_policy(remediation_policy, devices)
                )
            except Exception as e:
                logger.warning(f"Failed to audit remediation policy: {e}")
                if iteration == max_iterations - 1:
                    if best_yaml:
                        return best_yaml, best_result
                    raise
                continue

            new_compliance = new_audit_result.overall_compliance_percentage

            logger.info(
                f"Remediation policy compliance: {new_compliance:.1f}% "
                f"(improvement: {new_compliance - best_compliance:+.1f}%)"
            )

            # Check if we've improved
            if new_compliance > best_compliance:
                best_yaml = remediation_yaml
                best_result = new_audit_result
                best_compliance = new_compliance
                logger.info("✓ Improved compliance, keeping this version")
            else:
                logger.info("✗ No improvement, trying again")

            # If we've achieved 100% compliance, we're done
            if best_compliance >= 100.0:
                logger.info("✓ Achieved 100% compliance!")
                break

        # If we have a best YAML, return it
        if best_yaml is not None:
            return best_yaml, best_result

        # AI failed to produce a valid remediation; run programmatic fallback
        logger.warning("AI failed to generate valid remediation policy; using programmatic fallback")
        try:
            fallback_policy = self._programmatic_remediation_policy(audit_result, original_policy)
            fallback_yaml = fallback_policy.export_to_yaml()

            # Audit the fallback policy
            fallback_audit = asyncio.run(self.audit_engine.audit_policy(fallback_policy, devices))

            logger.info(
                f"Programmatic remediation compliance: {fallback_audit.overall_compliance_percentage:.1f}%"
            )

            return fallback_yaml, fallback_audit
        except Exception as e:
            logger.exception("Programmatic remediation failed")
            raise RuntimeError("Failed to generate a valid remediation policy after all iterations") from e

    def _programmatic_remediation_policy(self, audit_result: PolicyAuditResult, original_policy: NetworkPolicy) -> NetworkPolicy:
        """Create a conservative remediation policy programmatically.

        Strategy:
        - Start from the original policy
        - For each missing_rule issue, ensure the corresponding policy rule exists (add if absent)
        - For each misconfigured_rule, prefer the policy's expected configuration when available
        - Keep extra_rule documented but do not remove automatically
        This approach favors applying the declared desired policy rather than aggressive removals.
        """
        # Start with a deep copy of original policy (via dict round-trip)
        policy_dict = original_policy.model_dump(mode="json")
        fallback = NetworkPolicy.from_dict(policy_dict)

        # Helper: find policy rule by id or name
        def find_policy_rule(rule_id: Optional[str], rule_name: Optional[str]):
            if rule_id:
                for r in original_policy.get_all_rules():
                    if getattr(r, "id", None) == rule_id:
                        return r
            if rule_name:
                for r in original_policy.get_all_rules():
                    if getattr(r, "name", None) == rule_name:
                        return r
            return None

        # Iterate device results and their issues
        for device_result in audit_result.device_results:
            for issue in device_result.issues:
                try:
                    if issue.issue_type == "missing_rule":
                        # Ensure the rule exists in fallback policy
                        rule = find_policy_rule(issue.rule_id, issue.rule_name)
                        if rule is None and issue.expected_config:
                            # Try to construct from expected_config if it's a dict
                            if isinstance(issue.expected_config, dict):
                                new_rule = FirewallRule()
                                # best-effort apply fields from dict
                                for k, v in issue.expected_config.items():
                                    if hasattr(new_rule, k):
                                        try:
                                            setattr(new_rule, k, v)
                                        except Exception:
                                            # ignore non-assignable fields
                                            pass
                                fallback.add_firewall_rule(new_rule)
                        # If rule exists in original policy, ensure it's present (it already is)

                    elif issue.issue_type == "misconfigured_rule":
                        # Try to replace with expected_config if available
                        rule = find_policy_rule(issue.rule_id, issue.rule_name)
                        if rule and issue.expected_config:
                            # If expected_config is a FirewallRule or dict, update rule
                            if hasattr(issue.expected_config, "model_dump"):
                                expected = issue.expected_config
                                # Replace attributes from expected
                                for k, v in expected.model_dump().items():
                                    if hasattr(rule, k):
                                        try:
                                            setattr(rule, k, v)
                                        except Exception:
                                            pass
                            elif isinstance(issue.expected_config, dict):
                                for k, v in issue.expected_config.items():
                                    if hasattr(rule, k):
                                        try:
                                            setattr(rule, k, v)
                                        except Exception:
                                            pass

                    # For extra_rule, document but do not remove
                except Exception:
                    logger.exception(
                        f"Failed to apply programmatic remediation for issue: {issue}"
                    )

        return fallback

    def save_remediation_policy(self, remediation_yaml: str, output_path: Path) -> None:
        """Save remediation policy to a file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            f.write(remediation_yaml)

        logger.info(f"Saved remediation policy to {output_path}")

    def generate_summary_report(
        self,
        original_result: PolicyAuditResult,
        remediation_result: PolicyAuditResult,
    ) -> str:
        """Generate a summary report comparing original and remediation results."""
        report = f"""# AI Remediation Summary

## Original Policy: {original_result.policy_name}
- Compliance: {original_result.overall_compliance_percentage:.1f}%
- Total Issues: {original_result.total_issues}
- Non-compliant Devices: {original_result.non_compliant_devices}/{original_result.devices_audited}

### Issues by Severity (Original)
"""
        for severity in ["critical", "high", "medium", "low"]:
            issues = original_result.get_issues_by_severity(severity)
            if issues:
                report += f"- {severity.upper()}: {len(issues)}\n"

        report += f"""

## Remediation Policy: {remediation_result.policy_name}
- Compliance: {remediation_result.overall_compliance_percentage:.1f}%
- Total Issues: {remediation_result.total_issues}
- Non-compliant Devices: {remediation_result.non_compliant_devices}/{remediation_result.devices_audited}

### Issues by Severity (Remediation)
"""
        for severity in ["critical", "high", "medium", "low"]:
            issues = remediation_result.get_issues_by_severity(severity)
            if issues:
                report += f"- {severity.upper()}: {len(issues)}\n"

        # Calculate improvements
        compliance_improvement = (
            remediation_result.overall_compliance_percentage
            - original_result.overall_compliance_percentage
        )
        issues_fixed = original_result.total_issues - remediation_result.total_issues

        report += f"""

## Results
- Compliance Improvement: {compliance_improvement:+.1f}%
- Issues Fixed: {issues_fixed}
- Status: {"✓ SUCCESS" if remediation_result.overall_compliance_percentage >= 100.0 else "⚠ PARTIAL"}
"""

        if remediation_result.total_issues > 0:
            report += "\n### Remaining Issues\n"
            for device_result in remediation_result.device_results:
                if device_result.issues:
                    report += f"\n**{device_result.device}**:\n"
                    for issue in device_result.issues[:5]:  # Show first 5
                        report += f"- [{issue.severity}] {issue.description}\n"

        return report
