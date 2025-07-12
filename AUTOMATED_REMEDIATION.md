# Automated Remediation Guide

This guide covers AuditAgent's advanced automated remediation capabilities that can automatically fix detected compliance issues instead of just reporting them.

## Overview

The automated remediation system provides intelligent, risk-aware enforcement that can:

- **Automatically fix compliance issues** detected during audits
- **Assess and manage risk** with configurable strategies
- **Provide rollback capabilities** for failed changes
- **Validate fixes** after execution
- **Generate comprehensive reports** with detailed action logs

## Key Features

### 🛡️ Safety First
- **Dry-run mode**: Test all changes before applying them
- **Pre-execution validation**: Check commands before running
- **Post-execution verification**: Confirm fixes worked correctly
- **Automatic rollback**: Undo changes if something fails
- **Risk assessment**: Categorize actions by potential impact

### 🎯 Smart Strategies
- **Conservative**: Only fix low-risk issues
- **Balanced**: Fix low and medium-risk issues (default)
- **Aggressive**: Fix all issues except critical ones

### 🔧 Comprehensive Actions
- **Add missing rules**: Implement required security policies
- **Remove extra rules**: Clean up unauthorized configurations
- **Modify misconfigured rules**: Fix existing rule parameters
- **Fix connectivity issues**: Resolve basic device problems

## Quick Start

### 1. Basic Automated Remediation

```bash
# Dry run with default balanced strategy
python -m audit_agent.cli auto-remediate policy.yaml devices.yaml

# Apply fixes with conservative strategy
python -m audit_agent.cli auto-remediate \
    --strategy conservative \
    --no-dry-run \
    policy.yaml devices.yaml
```

### 2. Using Different Strategies

```bash
# Conservative: Only low-risk fixes
python -m audit_agent.cli auto-remediate \
    --strategy conservative \
    policy.yaml devices.yaml

# Balanced: Low and medium-risk fixes (default)
python -m audit_agent.cli auto-remediate \
    --strategy balanced \
    policy.yaml devices.yaml

# Aggressive: All fixes except critical
python -m audit_agent.cli auto-remediate \
    --strategy aggressive \
    policy.yaml devices.yaml
```

### 3. Advanced Options

```bash
# Continue on errors instead of stopping
python -m audit_agent.cli auto-remediate \
    --no-stop-on-error \
    --no-dry-run \
    policy.yaml devices.yaml

# Save detailed report to file
python -m audit_agent.cli auto-remediate \
    --output-file remediation-report.txt \
    --output-format text \
    policy.yaml devices.yaml
```

## Programmatic Usage

### Basic Example

```python
import asyncio
from audit_agent.core.policy import NetworkPolicy
from audit_agent.devices.linux_iptables import LinuxIptables
from audit_agent.enforcement.engine import EnhancedEnforcementEngine
from audit_agent.enforcement.remediation import RemediationStrategy

async def remediate_devices():
    # Load policy
    policy = NetworkPolicy.from_yaml_file("policy.yaml")
    
    # Configure devices
    devices = [
        LinuxIptables(host="server1.example.com", username="admin"),
        LinuxIptables(host="server2.example.com", username="admin"),
    ]
    
    # Create enforcement engine with balanced strategy
    engine = EnhancedEnforcementEngine(RemediationStrategy.BALANCED)
    
    # Run automated remediation
    result = await engine.auto_enforce_policy(
        policy=policy,
        devices=devices,
        dry_run=True,  # Set to False for actual changes
        use_smart_remediation=True,
        stop_on_error=True
    )
    
    # Generate report
    report = engine.generate_enhanced_enforcement_report(result)
    print(report)
    
    return result

# Run the remediation
result = asyncio.run(remediate_devices())
```

### Advanced Configuration

```python
from audit_agent.enforcement.remediation import (
    RemediationPlanner,
    RemediationExecutor,
    AutomatedRemediationManager
)

# Create custom remediation manager
manager = AutomatedRemediationManager(RemediationStrategy.CONSERVATIVE)

# Run just the planning phase
audit_result = await audit_engine.audit_policy(policy, devices)
plan = await manager.planner.create_remediation_plan(policy, audit_result)

print(f"Plan created with {plan.total_actions} actions")
print(f"Estimated time: {plan.estimated_total_time:.1f} seconds")
print(f"Risk assessment: {plan.risk_assessment}")

# Execute the plan separately
executor = RemediationExecutor()
result = await executor.execute_remediation_plan(plan, dry_run=False)
```

## Remediation Strategies

### Conservative Strategy
- **Risk tolerance**: Low only
- **Best for**: Production environments, critical systems
- **Actions**: 
  - Add deny/block rules
  - Remove obviously unauthorized rules
  - Basic security hardening
- **Avoids**: 
  - Allow rules that might open access
  - Complex rule modifications
  - System service changes

### Balanced Strategy (Default)
- **Risk tolerance**: Low and medium
- **Best for**: Most environments, regular maintenance
- **Actions**:
  - All conservative actions
  - Add restrictive allow rules
  - Modify existing rules to match policy
  - Basic connectivity fixes
- **Avoids**:
  - Overly permissive allow rules
  - Critical service modifications
  - High-risk connectivity changes

### Aggressive Strategy
- **Risk tolerance**: Low, medium, and high
- **Best for**: Development environments, major remediation efforts
- **Actions**:
  - All balanced actions
  - Add any allow rules defined in policy
  - Comprehensive rule modifications
  - Service restart and configuration fixes
- **Avoids**:
  - Only critical-risk actions that could cause outages

## Safety Features

### Pre-execution Validation
Before executing any action, the system:
- Validates command syntax
- Checks for device connectivity
- Identifies potential conflicts
- Assesses risk levels
- Verifies rollback commands

### Post-execution Verification
After executing actions, the system:
- Runs validation commands to confirm success
- Checks that intended changes were applied
- Verifies no unintended side effects occurred
- Updates action status based on results

### Automatic Rollback
If an action fails or validation fails:
- Automatically executes rollback commands
- Attempts to restore previous state
- Logs rollback success or failure
- Continues with remaining actions (if configured)

### Risk Assessment
Each action is categorized by risk level:
- **Low**: Unlikely to cause issues (e.g., add deny rules)
- **Medium**: Some risk but generally safe (e.g., modify rule parameters)
- **High**: Potential for service impact (e.g., restart services)
- **Critical**: Could cause outages (automatically excluded)

## Monitoring and Reporting

### Comprehensive Logging
All activities are logged with:
- Timestamp and duration
- Command executed and result
- Success/failure status
- Error messages and diagnostics
- Rollback actions taken

### Detailed Reports
Reports include:
- Executive summary with success rates
- Action-by-action breakdown
- Risk assessment and mitigation
- Device-specific results
- Recommendations for failed actions

### Integration with Audit Reports
- Compare before/after compliance states
- Track improvement metrics over time
- Identify recurring issues
- Plan future remediation cycles

## Best Practices

### Planning and Preparation
1. **Start with audits**: Always audit before remediation
2. **Review policies**: Ensure your policies are correct and complete
3. **Test in dev**: Use development environments for testing
4. **Use dry-run**: Always test with `--dry-run` first
5. **Check connectivity**: Ensure all devices are accessible

### Execution Strategy
1. **Start conservative**: Begin with conservative strategy
2. **Schedule wisely**: Run during maintenance windows
3. **Monitor closely**: Watch for issues during execution
4. **Have rollback plans**: Prepare manual rollback procedures
5. **Stop on errors**: Use `--stop-on-error` for initial runs

### Post-remediation
1. **Verify results**: Check that fixes were applied correctly
2. **Re-audit devices**: Confirm compliance improvements
3. **Monitor stability**: Watch for any service disruptions
4. **Document changes**: Keep records of what was changed
5. **Plan next cycle**: Schedule regular remediation runs

## Troubleshooting

### Common Issues

#### "No actions generated"
- Check that policy rules are properly defined
- Verify devices are accessible and returning configurations
- Ensure policy rules don't already match device state

#### "Pre-execution validation failed"
- Review command syntax in generated actions
- Check device connectivity and credentials
- Verify sufficient privileges for target actions

#### "Post-execution verification failed"
- Check if commands were actually applied
- Look for permission or syntax errors
- Review device logs for additional context

#### "Rollback failed"
- May indicate more serious device issues
- Check device connectivity and state
- Consider manual intervention to restore service

### Getting Help
1. **Increase verbosity**: Use `-v` or `-vv` for detailed logs
2. **Check audit reports**: Review initial compliance issues
3. **Test manually**: Try individual commands on devices
4. **Review documentation**: Check device-specific implementation guides
5. **Contact support**: Provide logs and configuration details

## Examples and Use Cases

### Example 1: Regular Compliance Maintenance
```bash
# Weekly automated compliance fix
python -m audit_agent.cli auto-remediate \
    --strategy balanced \
    --no-dry-run \
    --output-file "weekly-remediation-$(date +%Y%m%d).txt" \
    corporate-security-policy.yaml \
    production-servers.yaml
```

### Example 2: New Server Deployment
```bash
# Apply security hardening to new servers
python -m audit_agent.cli auto-remediate \
    --strategy aggressive \
    --no-dry-run \
    hardening-policy.yaml \
    new-servers.yaml
```

### Example 3: Security Incident Response
```bash
# Quick security fixes during incident
python -m audit_agent.cli auto-remediate \
    --strategy conservative \
    --no-dry-run \
    --stop-on-error \
    incident-response-policy.yaml \
    affected-devices.yaml
```

---

For more information, see the [main README](../README.md) and [examples directory](../examples/).
