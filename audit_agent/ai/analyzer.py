"""
Audit result analyzer for AI-powered remediation.
"""

import json
from typing import Any

from ..audit.engine import ComplianceIssue, PolicyAuditResult
from ..core.logging_config import get_logger

logger = get_logger(__name__)


class AuditResultAnalyzer:
    """Analyzes audit results and prepares them for AI processing."""

    def __init__(self):
        pass

    def analyze(self, audit_result: PolicyAuditResult) -> dict[str, Any]:
        """Analyze audit result and extract key information."""
        analysis = {
            "policy_name": audit_result.policy_name,
            "overall_compliance": audit_result.overall_compliance_percentage,
            "total_issues": audit_result.total_issues,
            "devices": [],
            "issues_by_severity": {},
            "issues_by_type": {},
        }

        # Analyze by severity
        for severity in ["critical", "high", "medium", "low", "info"]:
            issues = audit_result.get_issues_by_severity(severity)
            if issues:
                analysis["issues_by_severity"][severity] = len(issues)

        # Analyze by type
        issue_types = {}
        for device_result in audit_result.device_results:
            device_info = {
                "device_name": str(device_result.device),
                "compliance_percentage": device_result.compliance_percentage,
                "total_issues": len(device_result.issues),
                "issues": [],
            }

            for issue in device_result.issues:
                issue_info = self._serialize_issue(issue)
                device_info["issues"].append(issue_info)

                # Track by type
                if issue.issue_type not in issue_types:
                    issue_types[issue.issue_type] = 0
                issue_types[issue.issue_type] += 1

            analysis["devices"].append(device_info)

        analysis["issues_by_type"] = issue_types

        return analysis

    def _serialize_issue(self, issue: ComplianceIssue) -> dict[str, Any]:
        """Serialize a ComplianceIssue to a dictionary."""
        issue_dict = {
            "severity": issue.severity,
            "issue_type": issue.issue_type,
            "description": issue.description,
            "recommendation": issue.recommendation,
        }

        if issue.rule_id:
            issue_dict["rule_id"] = issue.rule_id
        if issue.rule_name:
            issue_dict["rule_name"] = issue.rule_name
        if issue.current_config:
            issue_dict["current_config"] = issue.current_config

        # Handle expected_config (might be FirewallRule object)
        if issue.expected_config:
            if hasattr(issue.expected_config, "model_dump"):
                # Pydantic model
                issue_dict["expected_config"] = issue.expected_config.model_dump()
            elif hasattr(issue.expected_config, "__dict__"):
                # Regular class with __dict__
                issue_dict["expected_config"] = self._serialize_rule(
                    issue.expected_config
                )
            else:
                # String or other primitive
                issue_dict["expected_config"] = str(issue.expected_config)

        return issue_dict

    def _serialize_rule(self, rule: Any) -> dict[str, Any]:
        """Serialize a rule object to dictionary."""
        if hasattr(rule, "model_dump"):
            return rule.model_dump()

        # Fallback: manual serialization
        rule_dict = {}
        for key, value in rule.__dict__.items():
            if key.startswith("_"):
                continue

            # Handle enums
            if hasattr(value, "value"):
                rule_dict[key] = value.value
            # Handle lists
            elif isinstance(value, list):
                rule_dict[key] = [
                    self._serialize_value(v) for v in value if v is not None
                ]
            # Handle other objects
            elif hasattr(value, "__dict__"):
                rule_dict[key] = self._serialize_value(value)
            # Primitives
            else:
                rule_dict[key] = value

        return rule_dict

    def _serialize_value(self, value: Any) -> Any:
        """Serialize any value to JSON-compatible format."""
        if value is None:
            return None
        if hasattr(value, "value"):
            return value.value
        if hasattr(value, "model_dump"):
            return value.model_dump()
        if hasattr(value, "__dict__"):
            return str(value)
        return value

    def generate_prompt(self, analysis: dict[str, Any]) -> str:
        """Generate a detailed prompt for AI analysis."""
        prompt = f"""You are a network security expert analyzing firewall policy compliance issues.

# Audit Summary
- Policy: {analysis["policy_name"]}
- Overall Compliance: {analysis["overall_compliance"]:.1f}%
- Total Issues: {analysis["total_issues"]}

# Issues by Severity
"""
        for severity, count in analysis.get("issues_by_severity", {}).items():
            prompt += f"- {severity.upper()}: {count}\n"

        prompt += "\n# Issues by Type\n"
        for issue_type, count in analysis.get("issues_by_type", {}).items():
            prompt += f"- {issue_type}: {count}\n"

        prompt += "\n# Device-Level Details\n"
        for device in analysis["devices"]:
            prompt += f"\n## Device: {device['device_name']}\n"
            prompt += f"- Compliance: {device['compliance_percentage']:.1f}%\n"
            prompt += f"- Issues: {device['total_issues']}\n\n"

            for issue in device["issues"]:
                prompt += f"### {issue['severity'].upper()}: {issue['issue_type']}\n"
                prompt += f"**Description**: {issue['description']}\n"
                prompt += f"**Recommendation**: {issue['recommendation']}\n"

                if "rule_name" in issue:
                    prompt += f"**Rule**: {issue['rule_name']}\n"

                if "expected_config" in issue and isinstance(
                    issue["expected_config"], dict
                ):
                    prompt += "**Expected Configuration**:\n"
                    prompt += f"```json\n{json.dumps(issue['expected_config'], indent=2)}\n```\n"

                prompt += "\n"

        return prompt

    def generate_remediation_request(
        self, analysis: dict[str, Any], original_policy_yaml: str
    ) -> str:
        """Generate a specific request for AI to create remediation policy."""
        prompt = self.generate_prompt(analysis)

        prompt += """

# Your Task
Analyze the compliance issues above and generate a complete remediation policy in YAML format.

## Requirements:
1. Include ALL rules from the original policy (provided below)
2. Add or modify rules to fix ALL compliance issues
3. For missing_rule issues: Add the missing firewall rules
4. For misconfigured_rule issues: Update the rule configuration
5. For extra_rule issues: Document them but don't remove (they may be system rules)
6. Ensure all logging requirements are met
7. Maintain proper rule priorities

## Original Policy (for reference):
```yaml
"""
        prompt += original_policy_yaml
        prompt += """
```

## Output Format:
Generate a complete NetworkPolicy YAML file that will achieve 100% compliance.
Include metadata with:
- name: "{original_name}-ai-remediation"
- description: "AI-generated remediation policy to fix all compliance issues"
- Include a summary of changes made

Respond with ONLY the YAML policy, no explanations before or after.
"""

        return prompt
