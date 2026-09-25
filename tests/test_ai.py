"""
Tests for AI integration.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import yaml

from audit_agent.ai.analyzer import AuditResultAnalyzer
from audit_agent.ai.config import AIConfig, AIProvider, ProviderConfig
from audit_agent.ai.providers import OpenCodeProvider, get_provider
from audit_agent.ai.remediation import AIRemediationEngine
from audit_agent.audit.engine import (
    ComplianceIssue,
    DeviceAuditResult,
    PolicyAuditResult,
)
from audit_agent.core.policy import NetworkPolicy
from audit_agent.core.rules import FirewallRule


@pytest.fixture
def sample_policy():
    """Create a sample policy for testing."""
    policy = NetworkPolicy("test-policy")
    rule = FirewallRule(name="allow-ssh", description="Allow SSH")
    rule.allow_inbound().tcp().port(22)
    policy.add_firewall_rule(rule)
    return policy


@pytest.fixture
def sample_audit_result():
    """Create a sample audit result with issues."""
    # Mock device
    mock_device = MagicMock()
    mock_device.__str__ = MagicMock(return_value="test-device")

    # Create compliance issues
    issues = [
        ComplianceIssue(
            severity="high",
            rule_id="rule1",
            rule_name="allow-ssh",
            issue_type="missing_rule",
            description="SSH rule is missing",
            device="test-device",
            recommendation="Add SSH rule",
        ),
        ComplianceIssue(
            severity="medium",
            rule_id="rule2",
            rule_name="allow-http",
            issue_type="misconfigured_rule",
            description="HTTP rule misconfigured",
            device="test-device",
            recommendation="Fix HTTP rule",
            current_config="wrong config",
        ),
    ]

    # Create device result
    device_result = DeviceAuditResult(
        device=mock_device,
        total_rules_checked=3,
        compliant_rules=1,
        non_compliant_rules=2,
        issues=issues,
        compliance_percentage=33.33,
        audit_timestamp="2024-01-01T00:00:00",
    )

    # Create policy audit result
    return PolicyAuditResult(
        policy_name="test-policy",
        devices_audited=1,
        compliant_devices=0,
        non_compliant_devices=1,
        total_issues=2,
        device_results=[device_result],
        overall_compliance_percentage=33.33,
        audit_timestamp="2024-01-01T00:00:00",
    )


def _event_stream(*texts: str) -> str:
    """Build an OpenCode-style JSON event stream with the given text events."""
    lines = [json.dumps({"type": "step_start", "part": {}})]
    for text in texts:
        lines.append(json.dumps({"type": "text", "part": {"text": text}}))
    return "\n".join(lines)


class TestAIConfig:
    """Test AI configuration management."""

    def test_load_from_env_defaults_to_opencode(self, monkeypatch):
        """OpenCode is the default provider and needs no API key."""
        monkeypatch.delenv("AI_PROVIDER", raising=False)
        monkeypatch.delenv("OPENCODE_MODEL", raising=False)

        config = AIConfig.load_from_env()

        assert config.default_provider == AIProvider.OPENCODE
        assert "opencode" in config.providers
        assert config.providers["opencode"].model == "opencode-go/deepseek-v4.1-flash"

    def test_load_from_env_model_override(self, monkeypatch):
        """OPENCODE_MODEL overrides the default model."""
        monkeypatch.setenv("OPENCODE_MODEL", "opencode-go/deepseek-v4.1-flash")
        monkeypatch.setenv("AI_PROVIDER", "opencode")

        config = AIConfig.load_from_env()

        assert config.default_provider == AIProvider.OPENCODE
        assert config.providers["opencode"].model == "opencode-go/deepseek-v4.1-flash"

    def test_load_from_env_invalid_provider_falls_back(self, monkeypatch):
        """An unknown AI_PROVIDER falls back to OpenCode."""
        monkeypatch.setenv("AI_PROVIDER", "does-not-exist")

        config = AIConfig.load_from_env()

        assert config.default_provider == AIProvider.OPENCODE

    def test_get_provider_config_success(self):
        """Test getting provider config."""
        config = AIConfig(
            providers={
                "opencode": ProviderConfig(model="opencode-go/deepseek-v4.1-flash")
            }
        )

        provider_config = config.get_provider_config(AIProvider.OPENCODE)
        assert provider_config.model == "opencode-go/deepseek-v4.1-flash"

    def test_get_provider_config_missing_provider(self):
        """Test error when provider config is missing."""
        config = AIConfig(providers={})

        with pytest.raises(ValueError, match="No configuration found"):
            config.get_provider_config(AIProvider.OPENCODE)

    def test_get_provider_config_needs_no_api_key(self):
        """OpenCode runs without an API key configured."""
        config = AIConfig(
            providers={"opencode": ProviderConfig(model="opencode-go/deepseek-v4.1-flash")}
        )

        provider_config = config.get_provider_config(AIProvider.OPENCODE)
        assert provider_config.api_key is None


class TestAuditResultAnalyzer:
    """Test audit result analyzer."""

    def test_analyze_audit_result(self, sample_audit_result):
        """Test analyzing audit results."""
        analyzer = AuditResultAnalyzer()
        analysis = analyzer.analyze(sample_audit_result)

        assert analysis["policy_name"] == "test-policy"
        assert analysis["overall_compliance"] == 33.33
        assert analysis["total_issues"] == 2

        # Check severity breakdown
        assert analysis["issues_by_severity"]["high"] == 1
        assert analysis["issues_by_severity"]["medium"] == 1

        # Check type breakdown
        assert analysis["issues_by_type"]["missing_rule"] == 1
        assert analysis["issues_by_type"]["misconfigured_rule"] == 1

        # Check device info
        assert len(analysis["devices"]) == 1
        assert analysis["devices"][0]["device_name"] == "test-device"
        assert len(analysis["devices"][0]["issues"]) == 2

    def test_generate_prompt(self, sample_audit_result):
        """Test generating AI prompt from analysis."""
        analyzer = AuditResultAnalyzer()
        analysis = analyzer.analyze(sample_audit_result)
        prompt = analyzer.generate_prompt(analysis)

        assert "test-policy" in prompt
        assert "33.3%" in prompt
        assert "HIGH: 1" in prompt
        assert "MEDIUM: 1" in prompt
        assert "missing_rule" in prompt
        assert "SSH rule is missing" in prompt

    def test_generate_remediation_request(self, sample_audit_result, sample_policy):
        """Test generating remediation request."""
        analyzer = AuditResultAnalyzer()
        analysis = analyzer.analyze(sample_audit_result)

        policy_yaml = yaml.dump(sample_policy.model_dump())
        request = analyzer.generate_remediation_request(analysis, policy_yaml)

        assert "test-policy" in request
        assert "missing_rule" in request
        assert "YAML" in request
        assert "100% compliance" in request


class TestOpenCodeProvider:
    """Test OpenCode provider implementation."""

    def test_extract_text_from_event_stream(self):
        """Text events are concatenated; non-text events ignored."""
        stdout = _event_stream("Hello ", "world")
        assert OpenCodeProvider._extract_text(stdout) == "Hello world"

    def test_extract_text_skips_noise(self):
        """Malformed / non-JSON lines are skipped without raising."""
        stdout = "not json\n" + _event_stream("ok") + "\n{broken"
        assert OpenCodeProvider._extract_text(stdout) == "ok"

    def test_default_model(self):
        """Provider falls back to the DEEPSEEK default model."""
        provider = OpenCodeProvider(ProviderConfig())
        assert provider.model == "opencode-go/deepseek-v4.1-flash"

    def test_generate_text_success(self):
        """Successful run returns the assistant text."""
        config = ProviderConfig(model="opencode-go/deepseek-v4.1-flash")
        provider = OpenCodeProvider(config)

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = _event_stream("Generated text")
        mock_proc.stderr = ""

        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            result = provider.generate_text("Test prompt")

            assert result == "Generated text"
            assert mock_run.called
            cmd = mock_run.call_args[0][0]
            assert "run" in cmd
            assert "--model" in cmd
            assert "opencode-go/deepseek-v4.1-flash" in cmd
            assert "--format" in cmd

    def test_generate_text_includes_system_prompt(self):
        """System prompt is folded into the message."""
        provider = OpenCodeProvider(ProviderConfig())

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = _event_stream("ok")
        mock_proc.stderr = ""

        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            provider.generate_text("Body", system_prompt="Be terse")

            message = mock_run.call_args[0][0][-1]
            assert "Be terse" in message
            assert "Body" in message

    def test_generate_text_retries_then_fails(self):
        """Non-zero exits exhaust retries and raise."""
        provider = OpenCodeProvider(ProviderConfig(max_retries=2))

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "boom"

        with patch("subprocess.run", return_value=mock_proc) as mock_run:
            with pytest.raises(RuntimeError, match="failed after 2 attempts"):
                provider.generate_text("Test prompt")

            assert mock_run.call_count == 2

    def test_generate_text_recovers_after_transient_failure(self):
        """A failure followed by success returns the successful text."""
        provider = OpenCodeProvider(ProviderConfig(max_retries=3))

        fail = MagicMock(returncode=1, stdout="", stderr="boom")
        ok = MagicMock(returncode=0, stdout=_event_stream("Recovered"), stderr="")

        with patch("subprocess.run", side_effect=[fail, ok]) as mock_run:
            result = provider.generate_text("Test prompt")

            assert result == "Recovered"
            assert mock_run.call_count == 2

    def test_generate_structured_output(self):
        """Structured output parses JSON, stripping code fences."""
        provider = OpenCodeProvider(ProviderConfig())

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = _event_stream('```json\n{"key": "value", "number": 42}\n```')
        mock_proc.stderr = ""

        with patch("subprocess.run", return_value=mock_proc):
            result = provider.generate_structured_output("Test prompt")

            assert isinstance(result, dict)
            assert result["key"] == "value"
            assert result["number"] == 42

    def test_missing_binary_raises(self):
        """A missing opencode binary produces a clear error."""
        provider = OpenCodeProvider(ProviderConfig(max_retries=1))

        with patch("subprocess.run", side_effect=FileNotFoundError()):
            with pytest.raises(RuntimeError, match="not found"):
                provider.generate_text("Test prompt")


class TestAIRemediationEngine:
    """Test AI remediation engine."""

    def test_clean_yaml_response(self):
        """Test cleaning YAML from AI response."""
        engine = AIRemediationEngine(
            AIConfig(providers={"opencode": ProviderConfig(model="test")})
        )

        # Test with markdown code block
        input_yaml = "```yaml\nmetadata:\n  name: test\n```"
        cleaned = engine._clean_yaml_response(input_yaml)
        assert cleaned == "metadata:\n  name: test"

        # Test with just backticks
        input_yaml = "```\nmetadata:\n  name: test\n```"
        cleaned = engine._clean_yaml_response(input_yaml)
        assert cleaned == "metadata:\n  name: test"

        # Test with plain YAML
        input_yaml = "metadata:\n  name: test"
        cleaned = engine._clean_yaml_response(input_yaml)
        assert cleaned == "metadata:\n  name: test"

    @patch("audit_agent.ai.remediation.get_provider")
    def test_generate_remediation_policy(
        self, mock_get_provider, sample_audit_result, sample_policy
    ):
        """Test generating remediation policy."""
        # Setup mock provider
        mock_provider = MagicMock()
        mock_provider.generate_text.return_value = """
metadata:
  name: test-policy-remediation
  version: '1.0'
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
        mock_get_provider.return_value = mock_provider

        config = AIConfig(
            providers={"opencode": ProviderConfig(model="test")}
        )
        engine = AIRemediationEngine(config)

        result = engine.generate_remediation_policy(sample_audit_result, sample_policy)

        assert "test-policy-remediation" in result
        assert "allow-ssh" in result
        assert mock_provider.generate_text.called

    def test_generate_summary_report(self, sample_audit_result):
        """Test generating summary report."""
        config = AIConfig(
            providers={"opencode": ProviderConfig(model="test")}
        )
        engine = AIRemediationEngine(config)

        # Create improved result
        improved_result = PolicyAuditResult(
            policy_name="test-policy-remediation",
            devices_audited=1,
            compliant_devices=1,
            non_compliant_devices=0,
            total_issues=0,
            device_results=[],
            overall_compliance_percentage=100.0,
            audit_timestamp="2024-01-01T00:00:00",
        )

        report = engine.generate_summary_report(sample_audit_result, improved_result)

        assert "AI Remediation Summary" in report
        assert "test-policy" in report
        assert "33.3%" in report
        assert "100.0%" in report
        assert "+66.7%" in report
        assert "SUCCESS" in report


class TestProviderFactory:
    """Test provider factory function."""

    def test_get_opencode_provider(self):
        """Test getting OpenCode provider."""
        config = AIConfig(
            default_provider=AIProvider.OPENCODE,
            providers={"opencode": ProviderConfig(model="test")},
        )

        provider = get_provider(config)
        assert isinstance(provider, OpenCodeProvider)

    def test_get_provider_missing_config(self):
        """Test error with missing provider configuration."""
        config = AIConfig(
            default_provider=AIProvider.OPENCODE,
            providers={},
        )

        with pytest.raises(ValueError, match="No configuration found"):
            get_provider(config)


@pytest.mark.integration
class TestAIIntegration:
    """Integration tests for AI functionality (requires OpenCode)."""

    def test_real_opencode_call(self):
        """Test a real OpenCode headless call (skip if unavailable/unauthed)."""
        import shutil

        if not shutil.which("opencode"):
            pytest.skip("opencode binary not installed")

        config = ProviderConfig(model="opencode-go/deepseek-v4.1-flash")
        provider = OpenCodeProvider(config)

        try:
            result = provider.generate_text("Reply with exactly one word: hello")
        except RuntimeError as e:
            # No credentials/model configured for this OpenCode install.
            pytest.skip(f"opencode not usable in this environment: {e}")

        assert len(result) > 0
        assert isinstance(result, str)
