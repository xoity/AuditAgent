"""
Command-line interface for AuditAgent.
"""

import asyncio
import json
from pathlib import Path
from typing import List, Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from .audit.engine import AuditEngine
from .core.logging_config import get_logger
from .core.policy import NetworkPolicy
from .core.rules import FirewallRule
from .devices.linux_iptables import LinuxIptables
from .enforcement.engine import EnforcementEngine
from .enforcement.remediation import RemediationStrategy

console = Console()


def version_callback(value: bool):
    if value:
        console.print("AuditAgent version 0.1.0")
        raise typer.Exit()


def help_callback(ctx: typer.Context, param: typer.CallbackParam, value: bool):
    if not value or ctx.resilient_parsing:
        return

    # Show comprehensive help
    console.print(
        "\n[bold blue]AuditAgent - Agentless Network Security Policy Enforcer & Auditor[/bold blue]\n"
    )

    console.print("[bold]USAGE:[/bold]")
    console.print("  python -m audit_agent.cli [COMMAND] [OPTIONS] [ARGUMENTS]\n")

    console.print("[bold]COMMANDS:[/bold]\n")

    # Audit command
    console.print(
        "[bold cyan]audit[/bold cyan] [italic]policy_file devices_file[/italic]"
    )
    console.print("  Audit devices against a network security policy")
    console.print("  [bold]Arguments:[/bold]")
    console.print(
        "    file1    Path to policy or devices file (YAML or JSON) [required]"
    )
    console.print(
        "    file2    Path to devices or policy file (YAML or JSON) [required]"
    )
    console.print("  [bold]Options:[/bold]")
    console.print(
        "    --output-format TEXT    Output format: text, json, html [default: text]"
    )
    console.print("    --output-file PATH      Output file path")
    console.print(
        "    --full-report           Show detailed issues for all severity levels"
    )
    console.print(
        "    -v, --verbose           Increase verbosity (-v, -vv) [default: 0]"
    )
    console.print("")

    # Enforce command
    console.print(
        "[bold cyan]enforce[/bold cyan] [italic]policy_file devices_file[/italic]"
    )
    console.print("  Enforce a network security policy on devices")
    console.print("  [bold]Arguments:[/bold]")
    console.print("    policy_file    Path to policy file (YAML or JSON) [required]")
    console.print("    devices_file   Path to devices configuration file [required]")
    console.print("  [bold]Options:[/bold]")
    console.print(
        "    --dry-run / --no-dry-run    Perform dry run without making changes [default: dry-run]"
    )
    console.print(
        "    --output-format TEXT        Output format: text, json [default: text]"
    )
    console.print("    --output-file PATH          Output file path")
    console.print(
        "    -v, --verbose               Increase verbosity (-v, -vv) [default: 0]"
    )
    console.print("")

    # Auto-remediate command
    console.print(
        "[bold cyan]auto-remediate[/bold cyan] [italic]policy_file devices_file[/italic]"
    )
    console.print("  Automatically remediate compliance issues using smart enforcement")
    console.print("  [bold]Arguments:[/bold]")
    console.print("    policy_file    Path to policy file (YAML or JSON) [required]")
    console.print("    devices_file   Path to devices configuration file [required]")
    console.print("  [bold]Options:[/bold]")
    console.print(
        "    --strategy TEXT             Remediation strategy: conservative, balanced, aggressive [default: balanced]"
    )
    console.print(
        "    --dry-run / --no-dry-run    Perform dry run without making changes [default: dry-run]"
    )
    console.print(
        "    --stop-on-error / --no-stop-on-error    Stop execution on first error [default: stop-on-error]"
    )
    console.print(
        "    --output-format TEXT        Output format: text, json [default: text]"
    )
    console.print("    --output-file PATH          Output file path")
    console.print(
        "    -v, --verbose               Increase verbosity (-v, -vv) [default: 0]"
    )
    console.print("")

    # Auto-generate command
    console.print(
        "[bold cyan]auto-generate[/bold cyan] [italic]policy_file devices_file[/italic]"
    )
    console.print("  Auto-generate remediation policy from audit results")
    console.print("  [bold]Arguments:[/bold]")
    console.print("    file1    Path to policy or devices file (YAML or JSON) [required]")
    console.print("    file2    Path to devices or policy file (YAML or JSON) [required]")
    console.print("  [bold]Options:[/bold]")
    console.print(
        "    --output-file PATH      Output file for remediation policy [default: remediation-policy.yaml]"
    )
    console.print(
        "    -v, --verbose           Increase verbosity (-v, -vv) [default: 0]"
    )
    console.print("")

    # Validate command
    console.print("[bold cyan]validate[/bold cyan] [italic]policy_file[/italic]")
    console.print("  Validate a network security policy for correctness")
    console.print("  [bold]Arguments:[/bold]")
    console.print("    policy_file    Path to policy file (YAML or JSON) [required]")
    console.print("  [bold]Options:[/bold]")
    console.print(
        "    --output-format TEXT    Output format: text, json [default: text]"
    )
    console.print("    --output-file PATH      Output file path")
    console.print("")

    # Create-example command
    console.print("[bold cyan]create-example[/bold cyan] [italic]output_file[/italic]")
    console.print("  Create an example network security policy")
    console.print("  [bold]Arguments:[/bold]")
    console.print("    output_file    Path for the example policy file [required]")
    console.print("  [bold]Options:[/bold]")
    console.print(
        "    --format TEXT    Format for the example: yaml, json [default: yaml]"
    )
    console.print("")

    console.print("[bold]GLOBAL OPTIONS:[/bold]")
    console.print("  -h, --help              Show this comprehensive help")
    console.print("  --version               Show version information")
    console.print("  --install-completion    Install completion for the current shell")
    console.print("  --show-completion       Show completion for current shell")
    console.print("")

    console.print("[bold]VERBOSITY LEVELS:[/bold]")
    console.print(
        "  [bold]Default[/bold]     Only show essential messages (warnings/errors)"
    )
    console.print(
        "  [bold]-v[/bold]         Show debug messages from AuditAgent modules"
    )
    console.print(
        "  [bold]-vv[/bold]        Show all debug messages including external libraries"
    )
    console.print("")

    console.print("[bold]EXAMPLES:[/bold]")
    console.print("  [dim]# Audit with minimal output[/dim]")
    console.print("  python -m audit_agent.cli audit policy.yaml devices.yaml")
    console.print("")
    console.print("  [dim]# Audit with debug output[/dim]")
    console.print("  python -m audit_agent.cli audit -v policy.yaml devices.yaml")
    console.print("")
    console.print("  [dim]# Enforce with dry run (default)[/dim]")
    console.print("  python -m audit_agent.cli enforce policy.yaml devices.yaml")
    console.print("")
    console.print("  [dim]# Enforce with actual changes[/dim]")
    console.print(
        "  python -m audit_agent.cli enforce --no-dry-run policy.yaml devices.yaml"
    )
    console.print("")
    console.print("  [dim]# Auto-generate remediation policy from audit results[/dim]")
    console.print(
        "  python -m audit_agent.cli auto-generate policy.yaml devices.yaml"
    )
    console.print("")
    console.print("  [dim]# Automated remediation with conservative strategy[/dim]")
    console.print(
        "  python -m audit_agent.cli auto-remediate --strategy conservative policy.yaml devices.yaml"
    )
    console.print("")
    console.print("  [dim]# Automated remediation with actual fixes[/dim]")
    console.print(
        "  python -m audit_agent.cli auto-remediate --no-dry-run policy.yaml devices.yaml"
    )
    console.print("")
    console.print("  [dim]# Validate policy file[/dim]")
    console.print("  python -m audit_agent.cli validate policy.yaml")
    console.print("")
    console.print("  [dim]# Create example policy[/dim]")
    console.print("  python -m audit_agent.cli create-example example-policy.yaml")

    raise typer.Exit()


app = typer.Typer(
    help="AuditAgent - Agentless Network Security Policy Enforcer & Auditor",
    no_args_is_help=True,
)
logger = get_logger(__name__)


@app.callback()
def main_callback(
    help: bool = typer.Option(
        False,
        "-h",
        "--help",
        callback=help_callback,
        is_eager=True,
        help="Show comprehensive help for all commands",
    ),
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show version information",
    ),
):
    """
    AuditAgent - Agentless Network Security Policy Enforcer & Auditor
    """
    pass


@app.command()
def audit(
    file1: Path = typer.Argument(
        ..., help="Path to policy or devices file (YAML or JSON)"
    ),
    file2: Path = typer.Argument(
        ..., help="Path to devices or policy file (YAML or JSON)"
    ),
    output_format: str = typer.Option("text", help="Output format: text, json, html"),
    output_file: Optional[Path] = typer.Option(None, help="Output file path"),
    full_report: bool = typer.Option(
        False, "--full-report", help="Show detailed issues for all severity levels"
    ),
    verbose: int = typer.Option(
        0, "-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)"
    ),
):
    """Audit devices against a network security policy."""

    # Setup logging based on verbosity
    from .core.logging_config import setup_logging

    setup_logging(min(verbose, 2))

    console.print("[bold blue]Starting Policy Audit...[/bold blue]")

    # Auto-detect file types
    policy_file, devices_file = auto_detect_file_types(file1, file2)

    # Load policy
    try:
        policy = load_policy(policy_file)
        console.print(f"✓ Loaded policy: {policy.metadata.name}")
        logger.info(f"Loaded policy: {policy.metadata.name}")
    except Exception as e:
        console.print(f"[red]Error loading policy: {e}[/red]")
        logger.error(f"Error loading policy: {e}")
        raise typer.Exit(1)

    # Load devices
    try:
        devices = load_devices(devices_file)
        console.print(f"✓ Loaded {len(devices)} devices")
        logger.info(f"Loaded {len(devices)} devices")
    except Exception as e:
        console.print(f"[red]Error loading devices: {e}[/red]")
        logger.error(f"Error loading devices: {e}")
        raise typer.Exit(1)

    # Run audit
    audit_engine = AuditEngine()

    console.print("Connecting to devices...")

    try:
        result = asyncio.run(audit_engine.audit_policy(policy, devices))
        console.print("✓ Audit completed")
        logger.info("Audit completed successfully")
    except Exception as e:
        console.print(f"[red]Error during audit: {e}[/red]")
        logger.error(f"Error during audit: {e}")
        raise typer.Exit(1)

    # Generate report
    report = audit_engine.generate_audit_report(result, output_format, full_report)

    if output_file:
        output_file.write_text(report)
        console.print(f"✓ Report saved to {output_file}")
        logger.info(f"Report saved to {output_file}")
    else:
        console.print(report)

    # Show summary
    display_audit_summary(result)


@app.command()
def enforce(
    file1: Path = typer.Argument(
        ..., help="Path to policy or devices file (YAML or JSON)"
    ),
    file2: Path = typer.Argument(
        ..., help="Path to devices or policy file (YAML or JSON)"
    ),
    dry_run: bool = typer.Option(True, help="Perform dry run without making changes"),
    output_format: str = typer.Option("text", help="Output format: text, json"),
    output_file: Optional[Path] = typer.Option(None, help="Output file path"),
    verbose: int = typer.Option(
        0, "-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)"
    ),
):
    """Enforce a network security policy on devices."""

    # Setup logging based on verbosity
    from .core.logging_config import setup_logging

    setup_logging(min(verbose, 2))

    mode_text = "DRY RUN" if dry_run else "LIVE ENFORCEMENT"
    console.print(
        f"[bold yellow]Starting Policy Enforcement ({mode_text})...[/bold yellow]"
    )

    if not dry_run:
        confirm = typer.confirm("This will make changes to your devices. Are you sure?")
        if not confirm:
            console.print("Enforcement cancelled.")
            logger.info("Enforcement cancelled by user")
            raise typer.Exit()

    # Auto-detect file types
    policy_file, devices_file = auto_detect_file_types(file1, file2)

    # Load policy and devices
    try:
        policy = load_policy(policy_file)
        devices = load_devices(devices_file)
        console.print(f"✓ Loaded policy: {policy.metadata.name}")
        console.print(f"✓ Loaded {len(devices)} devices")
        logger.info(f"Loaded policy: {policy.metadata.name}")
        logger.info(f"Loaded {len(devices)} devices")
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        logger.error(f"Error loading configuration: {e}")
        raise typer.Exit(1)

    # Run enforcement
    enforcement_engine = EnforcementEngine()

    console.print("Connecting to devices...")

    try:
        result = asyncio.run(
            enforcement_engine.enforce_policy(policy, devices, dry_run)
        )
        console.print("✓ Enforcement completed")
        logger.info("Enforcement completed successfully")
    except Exception as e:
        console.print(f"[red]Error during enforcement: {e}[/red]")
        logger.error(f"Error during enforcement: {e}")
        raise typer.Exit(1)

    # Generate report
    report = enforcement_engine.generate_enforcement_report(result, output_format)

    if output_file:
        output_file.write_text(report)
        console.print(f"✓ Report saved to {output_file}")
        logger.info(f"Report saved to {output_file}")
    else:
        console.print(report)

    # Show summary
    display_enforcement_summary(result)


@app.command()
def auto_remediate(
    file1: Path = typer.Argument(
        ..., help="Path to policy or devices file (YAML or JSON)"
    ),
    file2: Path = typer.Argument(
        ..., help="Path to devices or policy file (YAML or JSON)"
    ),
    strategy: str = typer.Option(
        "balanced", help="Remediation strategy: conservative, balanced, aggressive"
    ),
    dry_run: bool = typer.Option(True, help="Perform dry run without making changes"),
    stop_on_error: bool = typer.Option(True, help="Stop execution on first error"),
    output_format: str = typer.Option("text", help="Output format: text, json"),
    output_file: Optional[Path] = typer.Option(None, help="Output file path"),
    verbose: int = typer.Option(
        0, "-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)"
    ),
):
    """Automatically remediate compliance issues using smart enforcement."""

    # Setup logging based on verbosity
    from .core.logging_config import setup_logging

    setup_logging(min(verbose, 2))

    mode_text = "DRY RUN" if dry_run else "LIVE REMEDIATION"
    console.print(
        f"[bold green]Starting Automated Remediation ({mode_text})...[/bold green]"
    )

    if not dry_run:
        confirm = typer.confirm(
            "This will automatically fix compliance issues on your devices. Are you sure?"
        )
        if not confirm:
            console.print("Automated remediation cancelled.")
            logger.info("Automated remediation cancelled by user")
            raise typer.Exit()

    # Auto-detect file types
    policy_file, devices_file = auto_detect_file_types(file1, file2)

    # Load policy and devices
    try:
        policy = load_policy(policy_file)
        devices = load_devices(devices_file)
        console.print(f"✓ Loaded policy: {policy.metadata.name}")
        console.print(f"✓ Loaded {len(devices)} devices")
        logger.info(f"Loaded policy: {policy.metadata.name}")
        logger.info(f"Loaded {len(devices)} devices")
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        logger.error(f"Error loading configuration: {e}")
        raise typer.Exit(1)

    # Validate strategy
    try:
        remediation_strategy = RemediationStrategy(strategy.lower())
    except ValueError:
        console.print(f"[red]Invalid strategy: {strategy}[/red]")
        console.print("[red]Valid strategies: conservative, balanced, aggressive[/red]")
        raise typer.Exit(1)

    # Create enhanced enforcement engine with specified strategy
    from .enforcement.engine import EnhancedEnforcementEngine

    enforcement_engine = EnhancedEnforcementEngine(remediation_strategy)

    console.print("Connecting to devices and analyzing compliance...")

    try:
        result = asyncio.run(
            enforcement_engine.auto_enforce_policy(
                policy,
                devices,
                dry_run=dry_run,
                use_smart_remediation=True,
                stop_on_error=stop_on_error,
            )
        )
        console.print("✓ Automated remediation completed")
        logger.info("Automated remediation completed successfully")
    except Exception as e:
        console.print(f"[red]Error during automated remediation: {e}[/red]")
        logger.error(f"Error during automated remediation: {e}")
        raise typer.Exit(1)

    # Generate report
    report = enforcement_engine.generate_enhanced_enforcement_report(
        result, output_format
    )

    if output_file:
        output_file.write_text(report)
        console.print(f"✓ Report saved to {output_file}")
        logger.info(f"Report saved to {output_file}")
    else:
        console.print(report)

    # Show summary
    display_remediation_summary(result)


@app.command()
def validate(
    policy_file: Path = typer.Argument(..., help="Path to policy file (YAML or JSON)"),
):
    """Validate a network security policy for correctness."""

    console.print("[bold green]Validating Policy...[/bold green]")

    try:
        policy = load_policy(policy_file)
        console.print(f"✓ Loaded policy: {policy.metadata.name}")

        # Validate policy
        validation_result = policy.validate_policy()

        if validation_result.is_valid:
            console.print("[green]✓ Policy is valid![/green]")
        else:
            console.print("[red]✗ Policy validation failed[/red]")

            if validation_result.errors:
                console.print("\n[red]Errors:[/red]")
                for error in validation_result.errors:
                    console.print(f"  - {error}")

            if validation_result.warnings:
                console.print("\n[yellow]Warnings:[/yellow]")
                for warning in validation_result.warnings:
                    console.print(f"  - {warning}")

        # Show policy summary
        display_policy_summary(policy)

    except Exception as e:
        console.print(f"[red]Error validating policy: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def auto_generate(
    file1: Path = typer.Argument(
        ..., help="Path to policy or devices file (YAML or JSON)"
    ),
    file2: Path = typer.Argument(
        ..., help="Path to devices or policy file (YAML or JSON)"
    ),
    output_file: Path = typer.Option(
        None, help="Output file for remediation policy (default: remediation-policy.yaml)"
    ),
    verbose: int = typer.Option(
        0, "-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)"
    ),
):
    """
    Auto-generate remediation policy from audit results.
    
    This command will:
    1. Audit your devices against the policy
    2. Identify missing/incorrect rules
    3. Generate a remediation policy with fixes
    4. Save it to a file you can review and enforce
    """

    # Setup logging based on verbosity
    from .core.logging_config import setup_logging

    setup_logging(min(verbose, 2))

    console.print("[bold cyan]🔧 Auto-Generating Remediation Policy...[/bold cyan]\n")

    # Auto-detect file types
    policy_file, devices_file = auto_detect_file_types(file1, file2)

    # Load policy
    try:
        policy = load_policy(policy_file)
        console.print(f"✓ Loaded policy: {policy.metadata.name}")
        logger.info(f"Loaded policy: {policy.metadata.name}")
    except Exception as e:
        console.print(f"[red]Error loading policy: {e}[/red]")
        logger.error(f"Error loading policy: {e}")
        raise typer.Exit(1)

    # Load devices
    try:
        devices = load_devices(devices_file)
        console.print(f"✓ Loaded {len(devices)} devices")
        logger.info(f"Loaded {len(devices)} devices")
    except Exception as e:
        console.print(f"[red]Error loading devices: {e}[/red]")
        logger.error(f"Error loading devices: {e}")
        raise typer.Exit(1)

    # Run audit
    audit_engine = AuditEngine()
    console.print("\n[bold]Step 1:[/bold] Auditing devices...")

    try:
        result = asyncio.run(audit_engine.audit_policy(policy, devices))
        console.print("✓ Audit completed\n")
        logger.info("Audit completed successfully")
    except Exception as e:
        console.print(f"[red]Error during audit: {e}[/red]")
        logger.error(f"Error during audit: {e}")
        raise typer.Exit(1)

    # Check if there are any issues
    if result.total_issues == 0:
        console.print("[green]✓ No compliance issues found! Your devices are compliant.[/green]")
        console.print("[green]  No remediation policy needed.[/green]")
        return

    console.print(f"[yellow]Found {result.total_issues} compliance issues[/yellow]")
    console.print(f"  • Critical: {len(result.get_critical_issues())}")
    console.print(f"  • High: {len(result.get_high_issues())}")
    
    # Get medium and low issues manually
    all_issues = []
    for device_result in result.device_results:
        all_issues.extend(device_result.issues)
    medium_issues = [i for i in all_issues if hasattr(i, 'severity') and i.severity == 'medium']
    low_issues = [i for i in all_issues if hasattr(i, 'severity') and i.severity == 'low']
    
    console.print(f"  • Medium: {len(medium_issues)}")
    console.print(f"  • Low: {len(low_issues)}\n")

    # Generate remediation policy
    console.print("[bold]Step 2:[/bold] Generating remediation policy...")

    remediation_policy = NetworkPolicy(f"{policy.metadata.name}-remediation")
    remediation_policy.metadata.description = f"Auto-generated remediation policy for {policy.metadata.name}"
    remediation_policy.metadata.author = "AuditAgent Auto-Generate"

    # Track what we're adding
    rules_added = 0
    devices_covered = set()

    # Process each device's issues
    for device_result in result.device_results:
        if not device_result.issues:
            continue

        device_name = str(device_result.device) if hasattr(device_result, 'device') else 'unknown'
        devices_covered.add(device_name)

        for issue in device_result.issues:
            # Check if this is a missing rule issue
            if "missing from device" in issue.description.lower() or "required" in issue.description.lower():
                # Extract rule name from issue description
                # Format: "Required firewall rule 'rule-name' is missing from device"
                import re
                match = re.search(r"'([^']+)'", issue.description)
                if match:
                    rule_name = match.group(1)
                    
                    # Find the original rule in the policy
                    original_rule = None
                    for rule in policy.firewall_rules:
                        if rule.name == rule_name:
                            original_rule = rule
                            break
                    
                    # Add the rule to remediation policy if found
                    if original_rule:
                        # Check if we already added this rule
                        rule_exists = any(r.name == original_rule.name for r in remediation_policy.firewall_rules)
                        if not rule_exists:
                            remediation_policy.add_firewall_rule(original_rule)
                            rules_added += 1
                            console.print(f"  ✓ Added rule: {original_rule.name}")

    console.print(f"\n✓ Generated remediation policy with {rules_added} rules")
    console.print(f"  Covers {len(devices_covered)} device(s)\n")

    # Determine output file
    if not output_file:
        output_file = Path("remediation-policy.yaml")

    # Save remediation policy
    console.print(f"[bold]Step 3:[/bold] Saving remediation policy to {output_file}...")
    
    try:
        content = remediation_policy.export_to_yaml()
        output_file.write_text(content)
        console.print("✓ Remediation policy saved\n")
    except Exception as e:
        console.print(f"[red]Error saving remediation policy: {e}[/red]")
        raise typer.Exit(1)

    # Show what to do next
    console.print("[bold green]✓ Auto-Generation Complete![/bold green]\n")
    console.print("[bold cyan]Next Steps:[/bold cyan]")
    console.print(f"  1. Review the remediation policy: {output_file}")
    console.print("  2. Test with dry-run first:")
    console.print(f"     [dim]audit-agent enforce --dry-run {output_file} {devices_file}[/dim]")
    console.print("  3. Apply the fixes:")
    console.print(f"     [dim]audit-agent enforce --no-dry-run {output_file} {devices_file}[/dim]")
    console.print("  4. Or use auto-remediate:")
    console.print(f"     [dim]audit-agent auto-remediate {output_file} {devices_file}[/dim]\n")

    # Show policy summary
    console.print("[bold]Remediation Policy Summary:[/bold]")
    display_policy_summary(remediation_policy)


@app.command()
def create_example(
    output_file: Path = typer.Argument(..., help="Output file path for example policy"),
    format: str = typer.Option("yaml", help="Output format: yaml, json"),
):
    """Create an example network security policy."""

    console.print("Creating example policy...")

    # Create example policy
    policy = NetworkPolicy("example-web-server-policy")
    policy.metadata.description = "Example policy for web servers"
    policy.metadata.author = "AuditAgent"

    # Add zones
    dmz_zone = policy.add_zone("dmz")
    dmz_zone.add_network("192.168.100.0/24")
    dmz_zone.description = "DMZ for web servers"

    mgmt_zone = policy.add_zone("management")
    mgmt_zone.add_network("10.0.0.0/24")
    mgmt_zone.description = "Management network"

    # Add firewall rules
    # SSH access from management
    ssh_rule = (
        FirewallRule()
        .allow_inbound()
        .tcp()
        .port(22)
        .from_zone("management")
        .to_zone("dmz")
        .log()
        .priority_high()
    )
    ssh_rule.name = "allow-ssh-from-mgmt"
    ssh_rule.description = "Allow SSH from management network"
    policy.add_firewall_rule(ssh_rule)

    # HTTP/HTTPS access from anywhere
    web_rule = (
        FirewallRule()
        .allow_inbound()
        .tcp()
        .ports([80, 443])
        .from_any()
        .to_zone("dmz")
        .log()
    )
    web_rule.name = "allow-web-traffic"
    web_rule.description = "Allow web traffic to DMZ"
    policy.add_firewall_rule(web_rule)

    # Deny all other traffic
    deny_rule = (
        FirewallRule()
        .deny_inbound()
        .any_protocol()
        .from_any()
        .to_zone("dmz")
        .log()
        .priority_low()
    )
    deny_rule.name = "deny-all-other"
    deny_rule.description = "Deny all other traffic to DMZ"
    policy.add_firewall_rule(deny_rule)

    # Export policy
    if format.lower() == "yaml":
        content = policy.export_to_yaml()
    else:
        content = policy.export_to_json()

    output_file.write_text(content)
    console.print(f"✓ Example policy created: {output_file}")

    # Show summary
    display_policy_summary(policy)


def load_policy(policy_file: Path) -> NetworkPolicy:
    """Load a policy from file."""
    content = policy_file.read_text()

    if policy_file.suffix.lower() in [".yaml", ".yml"]:
        return NetworkPolicy.from_yaml(content)
    elif policy_file.suffix.lower() == ".json":
        return NetworkPolicy.from_json(content)
    else:
        raise ValueError(f"Unsupported policy file format: {policy_file.suffix}")


def auto_detect_file_types(file1: Path, file2: Path) -> tuple[Path, Path]:
    """Auto-detect which file is policy and which is devices based on content."""
    logger.debug(f"Auto-detecting file types for: {file1} and {file2}")

    def is_policy_file(file_path: Path) -> bool:
        """Check if a file contains policy content."""
        try:
            content = file_path.read_text()
            if file_path.suffix.lower() in [".yaml", ".yml"]:
                data = yaml.safe_load(content)
            elif file_path.suffix.lower() == ".json":
                data = json.loads(content)
            else:
                return False

            # Check for policy indicators
            policy_indicators = [
                "metadata",
                "firewall_rules",
                "zones",
                "nat_rules",
                "vpn_rules",
                "qos_rules",
            ]
            return any(key in data for key in policy_indicators)
        except Exception:
            return False

    def is_devices_file(file_path: Path) -> bool:
        """Check if a file contains devices content."""
        try:
            content = file_path.read_text()
            if file_path.suffix.lower() in [".yaml", ".yml"]:
                data = yaml.safe_load(content)
            elif file_path.suffix.lower() == ".json":
                data = json.loads(content)
            else:
                return False

            # Check for devices indicators
            return "devices" in data and isinstance(data["devices"], list)
        except Exception:
            return False

    # Determine which is which
    if is_policy_file(file1) and is_devices_file(file2):
        logger.debug(f"Detected: {file1} = policy, {file2} = devices")
        return file1, file2
    elif is_policy_file(file2) and is_devices_file(file1):
        logger.debug(f"Detected: {file2} = policy, {file1} = devices")
        return file2, file1
    else:
        # Fallback to original order if detection fails
        logger.warning("Could not auto-detect file types, using original order")
        return file1, file2


def load_devices(devices_file: Path) -> List:
    """Load device configurations from file."""
    logger.debug(f"Loading devices from: {devices_file}")
    content = devices_file.read_text()
    logger.debug(f"Device file content: {content}")

    if devices_file.suffix.lower() in [".yaml", ".yml"]:
        devices_config = yaml.safe_load(content)
    elif devices_file.suffix.lower() == ".json":
        devices_config = json.loads(content)
    else:
        raise ValueError(f"Unsupported devices file format: {devices_file.suffix}")

    logger.debug(f"Parsed device config: {devices_config}")
    devices = []

    for device_config in devices_config.get("devices", []):
        logger.debug(f"Processing device config: {device_config}")
        device_type = device_config.get("type", "").lower()
        logger.debug(f"Device type: {device_type}")

        if device_type == "linux_iptables":
            logger.debug("Creating LinuxIptables device...")

            # Check for deprecated hardcoded credentials
            deprecated_fields = []
            if device_config.get("password"):
                deprecated_fields.append("password")

            if deprecated_fields:
                console.print(
                    f"[yellow]⚠️  Warning: Device '{device_config.get('name', 'unnamed')}' has hardcoded credentials: {', '.join(deprecated_fields)}[/yellow]"
                )
                console.print(
                    "[yellow]   This is a security risk. Consider removing these fields and using dynamic prompting.[/yellow]"
                )

            device = LinuxIptables(
                host=device_config["host"],
                username=device_config["username"],
                password=device_config.get("password"),
                private_key=device_config.get("private_key"),
                port=device_config.get("port", 22),
                # Removed insecure credential fields
            )
            devices.append(device)
            logger.debug(f"Created device: {device}")
        else:
            console.print(
                f"[yellow]Warning: Unsupported device type: {device_type}[/yellow]"
            )
            console.print("[yellow]Supported types: linux_iptables[/yellow]")

    logger.debug(f"Total devices loaded: {len(devices)}")
    return devices


def display_audit_summary(result):
    """Display audit results summary."""
    console.print("\n[bold]Audit Summary[/bold]")

    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Overall Compliance", f"{result.overall_compliance_percentage:.1f}%")
    table.add_row("Devices Audited", str(result.devices_audited))
    table.add_row("Compliant Devices", str(result.compliant_devices))
    table.add_row("Non-Compliant Devices", str(result.non_compliant_devices))
    table.add_row("Total Issues", str(result.total_issues))
    table.add_row("Critical Issues", str(len(result.get_critical_issues())))
    table.add_row("High Priority Issues", str(len(result.get_high_issues())))

    console.print(table)


def display_enforcement_summary(result):
    """Display enforcement results summary."""
    console.print("\n[bold]Enforcement Summary[/bold]")

    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Mode", "DRY RUN" if result.dry_run else "LIVE")
    table.add_row("Overall Success Rate", f"{result.overall_success_rate:.1f}%")
    table.add_row("Devices Processed", str(result.devices_processed))
    table.add_row("Actions Planned", str(result.total_actions_planned))
    table.add_row("Actions Executed", str(result.total_actions_executed))
    table.add_row("Successful Actions", str(result.total_actions_successful))
    table.add_row("Failed Actions", str(result.total_actions_failed))

    console.print(table)


def display_remediation_summary(result):
    """Display automated remediation results summary."""
    console.print("\n[bold]Automated Remediation Summary[/bold]")

    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Strategy", result.plan.strategy.value.title())
    table.add_row("Mode", "DRY RUN" if getattr(result, "dry_run", False) else "LIVE")
    table.add_row("Overall Success Rate", f"{result.overall_success_rate:.1f}%")
    table.add_row("Total Actions", str(result.plan.total_actions))
    table.add_row("Actions Completed", str(result.actions_completed))
    table.add_row("Actions Failed", str(result.actions_failed))
    table.add_row("Actions Skipped", str(result.actions_skipped))
    table.add_row("Actions Rolled Back", str(result.actions_rolled_back))
    table.add_row("Execution Time", f"{result.total_execution_time:.1f}s")
    table.add_row("Risk Assessment", result.plan.risk_assessment.title())

    console.print(table)

    # Show status breakdown if there are any issues
    if result.actions_failed > 0 or result.actions_rolled_back > 0:
        console.print(
            "\n[yellow]⚠️  Some actions were not successful. Check the detailed report for more information.[/yellow]"
        )
    elif result.actions_skipped > 0:
        console.print(
            "\n[blue]ℹ️  Some actions were skipped due to dependencies or strategy constraints.[/blue]"
        )
    else:
        console.print(
            "\n[green]✅ All remediation actions completed successfully![/green]"
        )


def display_policy_summary(policy: NetworkPolicy):
    """Display policy summary."""
    console.print("\n[bold]Policy Summary[/bold]")

    table = Table()
    table.add_column("Component", style="cyan")
    table.add_column("Count", style="white")

    table.add_row("Zones", str(len(policy.zones)))
    table.add_row("Firewall Rules", str(len(policy.firewall_rules)))
    table.add_row("NAT Rules", str(len(policy.nat_rules)))
    table.add_row("VPN Rules", str(len(policy.vpn_rules)))
    table.add_row("QoS Rules", str(len(policy.qos_rules)))
    table.add_row("Total Rules", str(len(policy.get_all_rules())))

    console.print(table)


def main():
    """Main CLI entry point."""
    app()


if __name__ == "__main__":
    main()
