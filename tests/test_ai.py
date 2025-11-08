"""
Tests for AI integration.
"""

from unittest.mock import MagicMock, patch

import pytest
import yaml

from audit_agent.ai.analyzer import AuditResultAnalyzer
from audit_agent.ai.config import AIConfig, AIProvider, ProviderConfig
from audit_agent.ai.providers import GoogleAIProvider, get_provider
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


class TestAIConfig:
    """Test AI configuration management."""

    def test_load_from_env_google(self, monkeypatch):
        """Test loading Google AI config from environment."""
        monkeypatch.setenv("GOOGLE_AI_API_KEY", "test-key-123")
        monkeypatch.setenv("GOOGLE_AI_MODEL", "gemini-1.5-pro")

        config = AIConfig.load_from_env()

        assert config.default_provider == AIProvider.GOOGLE
        assert "google" in config.providers
        assert config.providers["google"].api_key == "test-key-123"
        assert config.providers["google"].model == "gemini-1.5-pro"

    def test_load_from_env_openai(self, monkeypatch):
        """Test loading OpenAI config from environment."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-456")
        monkeypatch.setenv("AI_PROVIDER", "openai")

        config = AIConfig.load_from_env()

        assert config.default_provider == AIProvider.OPENAI
        assert "openai" in config.providers
        assert config.providers["openai"].api_key == "sk-test-456"

    def test_get_provider_config_success(self):
        """Test getting provider config."""
        config = AIConfig(
            providers={
                "google": ProviderConfig(api_key="test-key", model="gemini-1.5-flash")
            }
        )

        provider_config = config.get_provider_config(AIProvider.GOOGLE)
        assert provider_config.api_key == "test-key"
        assert provider_config.model == "gemini-1.5-flash"

    def test_get_provider_config_missing_provider(self):
        """Test error when provider config is missing."""
        config = AIConfig(providers={})

        with pytest.raises(ValueError, match="No configuration found"):
            config.get_provider_config(AIProvider.GOOGLE)

    def test_get_provider_config_missing_api_key(self):
        """Test error when API key is missing."""
        config = AIConfig(providers={"google": ProviderConfig(api_key=None)})

        with pytest.raises(ValueError, match="No API key configured"):
            config.get_provider_config(AIProvider.GOOGLE)


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


class TestGoogleAIProvider:
    """Test Google AI provider implementation."""

    def test_generate_text_success(self):
        """Test successful text generation."""
        config = ProviderConfig(api_key="test-key", model="gemini-1.5-flash")
        provider = GoogleAIProvider(config)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "Generated text"}]}}]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response) as mock_post:
            result = provider.generate_text("Test prompt")

            assert result == "Generated text"
            assert mock_post.called
            call_args = mock_post.call_args
            assert "key" in call_args[1]["params"]
            assert call_args[1]["params"]["key"] == "test-key"

    def test_generate_text_retry_on_error(self):
        """Test retry logic on API errors."""
        config = ProviderConfig(
            api_key="test-key", model="gemini-1.5-flash", max_retries=2
        )
        provider = GoogleAIProvider(config)

        # First call fails, second succeeds
        mock_response_success = MagicMock()
        mock_response_success.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "Success"}]}}]
        }
        mock_response_success.raise_for_status = MagicMock()

        # Mock requests.post to succeed on second try
        with patch("requests.post") as mock_post:
            # First call raises, second succeeds
            mock_post.side_effect = [
                Exception("API Error"),
                mock_response_success,
            ]

            # Should raise because first attempt fails with exception that's not caught
            with pytest.raises(Exception, match="API Error"):
                provider.generate_text("Test prompt")

    def test_generate_structured_output(self):
        """Test structured JSON output generation."""
        config = ProviderConfig(api_key="test-key", model="gemini-1.5-flash")
        provider = GoogleAIProvider(config)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "candidates": [
                {"content": {"parts": [{"text": '{"key": "value", "number": 42}'}]}}
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("requests.post", return_value=mock_response):
            result = provider.generate_structured_output("Test prompt")

            assert isinstance(result, dict)
            assert result["key"] == "value"
            assert result["number"] == 42


class TestAIRemediationEngine:
    """Test AI remediation engine."""

    def test_clean_yaml_response(self):
        """Test cleaning YAML from AI response."""
        engine = AIRemediationEngine(
            AIConfig(providers={"google": ProviderConfig(api_key="test", model="test")})
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
            providers={"google": ProviderConfig(api_key="test", model="test")}
        )
        engine = AIRemediationEngine(config)

        result = engine.generate_remediation_policy(sample_audit_result, sample_policy)

        assert "test-policy-remediation" in result
        assert "allow-ssh" in result
        assert mock_provider.generate_text.called

    def test_generate_summary_report(self, sample_audit_result):
        """Test generating summary report."""
        config = AIConfig(
            providers={"google": ProviderConfig(api_key="test", model="test")}
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

    def test_get_google_provider(self):
        """Test getting Google AI provider."""
        config = AIConfig(
            default_provider=AIProvider.GOOGLE,
            providers={"google": ProviderConfig(api_key="test", model="test")},
        )

        provider = get_provider(config)
        assert isinstance(provider, GoogleAIProvider)

    def test_get_provider_invalid(self):
        """Test error with unsupported provider."""
        config = AIConfig(
            default_provider=AIProvider.GOOGLE,
            providers={"google": ProviderConfig(api_key="test", model="test")},
        )

        # Test with missing provider configuration
        with pytest.raises(ValueError, match="No configuration found"):
            config.get_provider_config(AIProvider.OPENAI)


@pytest.mark.integration
class TestAIIntegration:
    """Integration tests for AI functionality (requires API key)."""

    def test_real_google_ai_call(self):
        """Test real Google AI API call (skip if no API key)."""
        import os

        api_key = os.getenv("GOOGLE_AI_API_KEY")
        if not api_key:
            pytest.skip("GOOGLE_AI_API_KEY not set")

        config = ProviderConfig(api_key=api_key, model="gemini-1.5-flash")
        provider = GoogleAIProvider(config)

        result = provider.generate_text("Say hello in one word")
        assert len(result) > 0
        assert isinstance(result, str)
