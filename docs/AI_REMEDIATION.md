# AI-Powered Remediation Guide

AuditAgent includes advanced AI-powered remediation capabilities that use large language models to automatically analyze compliance issues and generate corrected firewall policies.

## Overview

The AI remediation system combines the power of modern AI models with deterministic validation to:

- **Automatically fix compliance violations** using intelligent policy analysis
- **Achieve 100% compliance** through iterative refinement
- **Generate human-readable explanations** for all changes
- **Provide fallback mechanisms** when AI is unavailable
- **Support multiple AI providers** (Google AI, OpenAI, Azure OpenAI)

## Quick Start

### 1. Set Up API Key

Get a free API key from [Google AI Studio](https://makersuite.google.com/app/apikey):

```bash
# Set your API key
export GOOGLE_AI_API_KEY="your-api-key-here"
```

### 2. Run AI Remediation

```bash
# Analyze and generate remediation (dry run)
audit-agent ai-remediate policy.yaml devices.yaml

# Apply the AI-generated fixes
audit-agent ai-remediate policy.yaml devices.yaml --apply

# Generate summary report
audit-agent ai-remediate policy.yaml devices.yaml --output-file report.md
```

## How It Works

### Step 1: Audit Current State

The system first audits all devices to identify compliance issues:

```plaintext
Step 1: Running initial audit...
  Compliance: 0.0%
  Total Issues: 5

  Issues by severity:
    • HIGH: 5
```

### Step 2: AI Analysis

The AI analyzes the issues and generates a corrected policy:

```plaintext
Step 2: Generating AI remediation policy...
  Calling AI provider: GoogleAIProvider
  Generated valid YAML policy
```

### Step 3: Iterative Refinement

The system validates the AI-generated policy and iterates if needed:

```plaintext
Remediation iteration 1/3 (current compliance: 0.0%)
  Remediation policy compliance: 100.0% (improvement: +100.0%)
  ✓ Improved compliance, keeping this version
  ✓ Achieved 100% compliance!
```

### Step 4: Apply Changes (Optional)

With `--apply`, the remediated policy is enforced on devices:

```plaintext
Step 4: Applying remediation policy...
  Actions Executed: 5
  Successful: 5
  Failed: 0

✓ Remediation applied successfully!
```

## AI Providers

### Google AI (Gemini) - Recommended

Free tier available, no credit card required:

```bash
export GOOGLE_AI_API_KEY="your-key"
export GOOGLE_AI_MODEL="gemini-2.0-flash-exp"  # Optional, uses default if not set
```

**Models supported:**

- `gemini-2.0-flash-exp` (default, recommended)
- `gemini-1.5-flash`
- `gemini-1.5-pro`

**Get API key:** <https://makersuite.google.com/app/apikey>

### OpenAI

```bash
export OPENAI_API_KEY="your-key"
export OPENAI_MODEL="gpt-4"  # or gpt-3.5-turbo

# Use OpenAI provider
audit-agent ai-remediate policy.yaml devices.yaml --provider openai
```

**Models supported:**

- `gpt-4` (recommended for complex policies)
- `gpt-3.5-turbo` (faster, less expensive)

### Azure OpenAI

```bash
export AZURE_OPENAI_API_KEY="your-key"
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com/"
export AZURE_OPENAI_DEPLOYMENT="your-deployment-name"

# Use Azure provider
audit-agent ai-remediate policy.yaml devices.yaml --provider azure
```

## Configuration

### Using Config File

Create `~/.audit-agent/config.yaml`:

```yaml
ai:
  default_provider: google
  providers:
    google:
      api_key: "your-google-ai-key"
      model: "gemini-2.0-flash-exp"
      max_retries: 3
      timeout: 30
    
    openai:
      api_key: "your-openai-key"
      model: "gpt-4"
      max_retries: 3
      timeout: 60
```

### Command Line Options

```bash
# Specify provider
audit-agent ai-remediate policy.yaml devices.yaml --provider google

# Set temperature (creativity level, 0.0-1.0)
audit-agent ai-remediate policy.yaml devices.yaml --temperature 0.3

# Maximum iterations for refinement
audit-agent ai-remediate policy.yaml devices.yaml --max-iterations 5

# Save outputs to specific files
audit-agent ai-remediate policy.yaml devices.yaml \
  --output-policy remediated-policy.yaml \
  --output-summary summary.md
```

## Advanced Features

### Iterative Refinement

The AI system can iterate up to 3 times (configurable) to improve compliance:

```bash
# Allow more iterations for complex policies
audit-agent ai-remediate policy.yaml devices.yaml --max-iterations 5
```

### Fallback Mechanism

If AI fails or is unavailable, the system uses deterministic fallback:

```plaintext
⚠ AI failed to generate valid remediation policy; using programmatic fallback
  Programmatic remediation compliance: 85.0%
```

### Policy Detection

The system intelligently detects when the policy is already correct:

```plaintext
All compliance issues are 'missing_rule' - this means the device lacks 
the rules defined in the policy. The policy itself appears correct.

ℹ  Policy is already correct - all issues are missing rules on the device.
   The remediation output is the original policy.
   Run with --apply to ENFORCE these rules on the device.
```

## Programmatic Usage

### Python API

```python
from audit_agent.ai.remediation import AIRemediationEngine
from audit_agent.core.policy import NetworkPolicy
from audit_agent.devices.linux_iptables import LinuxIptables
from audit_agent.audit.engine import AuditEngine
import asyncio

async def run_ai_remediation():
    # Load policy and devices
    policy = NetworkPolicy.from_yaml_file("policy.yaml")
    devices = [
        LinuxIptables(host="192.168.1.10", username="admin", 
                     private_key="~/.ssh/id_rsa")
    ]
    
    # Create engines
    audit_engine = AuditEngine()
    remediation_engine = AIRemediationEngine()
    
    # Run initial audit
    audit_result = await audit_engine.audit_policy(policy, devices)
    print(f"Initial compliance: {audit_result.overall_compliance_percentage:.1f}%")
    
    # Generate AI remediation
    remediation_yaml, final_result = remediation_engine.generate_and_validate(
        audit_result=audit_result,
        original_policy=policy,
        devices=devices,
        max_iterations=3
    )
    
    print(f"Final compliance: {final_result.overall_compliance_percentage:.1f}%")
    
    # Save remediated policy
    remediation_engine.save_remediation_policy(
        remediation_yaml, 
        Path("remediated-policy.yaml")
    )
    
    # Generate summary report
    summary = remediation_engine.generate_summary_report(
        audit_result, 
        final_result
    )
    print(summary)

# Run the remediation
asyncio.run(run_ai_remediation())
```

### Custom Provider Configuration

```python
from audit_agent.ai.config import AIConfig, ProviderConfig
from audit_agent.ai.remediation import AIRemediationEngine

# Configure custom provider
config = AIConfig(
    default_provider="google",
    providers={
        "google": ProviderConfig(
            api_key="your-key",
            model="gemini-2.0-flash-exp",
            temperature=0.3,
            max_retries=3
        )
    }
)

# Create engine with config
engine = AIRemediationEngine(config=config)
```

## Understanding the Output

### Remediation Summary Report

After AI remediation, you'll get a detailed markdown report:

```markdown
# AI Remediation Summary

## Original Policy: web-server-policy
- Compliance: 0.0%
- Total Issues: 5
- Non-compliant Devices: 1/1

### Issues by Severity (Original)
- HIGH: 5

## Remediation Policy: web-server-policy
- Compliance: 100.0%
- Total Issues: 0
- Non-compliant Devices: 0/1

## Results
- Compliance Improvement: +100.0%
- Issues Fixed: 5
- Status: ✓ SUCCESS
```

### Generated Policy Files

- `*-ai-remediation.yaml` - The AI-generated remediated policy
- `*-ai-remediation-summary.md` - Detailed summary report with before/after comparison

## Best Practices

### 1. Start with Dry Run

Always run without `--apply` first to review changes:

```bash
# Review AI recommendations
audit-agent ai-remediate policy.yaml devices.yaml

# Review generated files
cat policy-ai-remediation.yaml
cat policy-ai-remediation-summary.md

# Apply only if satisfied
audit-agent ai-remediate policy.yaml devices.yaml --apply
```

### 2. Use Version Control

Track changes to your policies:

```bash
git add policy.yaml
git commit -m "Original policy"

audit-agent ai-remediate policy.yaml devices.yaml --apply

git add policy-ai-remediation.yaml
git commit -m "AI-remediated policy"
```

### 3. Test in Development

Always test AI remediations in a development environment first:

```bash
# Dev environment
audit-agent ai-remediate dev-policy.yaml dev-devices.yaml --apply

# If successful, use in production
audit-agent ai-remediate prod-policy.yaml prod-devices.yaml --apply
```

### 4. Monitor API Usage

AI providers have rate limits and costs:

- **Google AI (Gemini)**: Free tier has 60 requests/minute
- **OpenAI**: Pay per token, costs vary by model
- **Azure OpenAI**: Based on your Azure subscription

### 5. Secure Your API Keys

```bash
# Use environment variables
export GOOGLE_AI_API_KEY="$(cat ~/.secrets/google-ai-key)"

# Or use config file with restricted permissions
chmod 600 ~/.audit-agent/config.yaml
```

## Troubleshooting

### "AI provider returned invalid YAML"

The AI sometimes generates explanatory text instead of pure YAML. The system automatically cleans this, but if it persists:

```bash
# Increase temperature for more deterministic output
audit-agent ai-remediate policy.yaml devices.yaml --temperature 0.1
```

### "Rate limit exceeded"

You're hitting API rate limits:

```bash
# For Google AI, wait a minute and retry
# For OpenAI, upgrade your tier or wait

# The system has built-in retry with exponential backoff
```

### "All issues are 'missing_rule'"

This is not an error - it means your policy is correct but not enforced:

```bash
# Just enforce the existing policy
audit-agent enforce policy.yaml devices.yaml --no-dry-run
```

### "No improvement in compliance"

The AI couldn't improve the policy further:

- Review the policy for logical errors
- Check if device configuration is unusual
- Try increasing `--max-iterations`
- Review audit results to understand specific issues

## Comparison: AI vs Programmatic Remediation

| Feature | AI Remediation | Programmatic Remediation |
|---------|---------------|--------------------------|
| **Intelligence** | Understands context and intent | Rule-based, deterministic |
| **Flexibility** | Adapts to complex scenarios | Limited to predefined patterns |
| **Speed** | Requires API calls (~2-5s) | Instant |
| **Accuracy** | Very high with proper policies | 100% predictable |
| **Cost** | API costs (free tier available) | Free |
| **Offline** | Requires internet | Works offline |
| **Use Case** | Complex policies, diverse issues | Simple policies, offline scenarios |

**Recommendation**: Use AI remediation for complex policies and critical systems. The programmatic fallback ensures the system always works even without AI.

## Future Enhancements

Planned features for AI remediation:

- 🌐 **Web UI integration** for visual policy editing
- 📊 **Compliance trend analysis** using AI
- 🤖 **Multi-step reasoning** for complex security scenarios
- 🔍 **Anomaly detection** in network traffic patterns
- 📝 **Natural language policy definition** ("Block all traffic from China")

## Security Considerations

### API Key Security

- Never commit API keys to version control
- Use environment variables or secure config files
- Rotate keys regularly
- Use separate keys for dev/prod

### Policy Review

- Always review AI-generated policies before applying
- Understand what changes are being made
- Test in non-production environments first
- Keep audit logs of all changes

### Data Privacy

- Policy data is sent to AI providers for analysis
- Review provider data retention policies
- For sensitive environments, use self-hosted models (coming soon)

## Related Documentation

- [Automated Remediation Guide](AUTOMATED_REMEDIATION.md) - Risk-based automated fixing
- [Configuration Guide](CONFIGURATION_GUIDE.md) - Policy and device configuration
- [Getting Started](GETTING_STARTED.md) - Basic usage and installation

---

**Questions or issues?** Open an issue on [GitHub](https://github.com/xoity/AuditAgent/issues)
