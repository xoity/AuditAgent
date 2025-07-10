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
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .audit.engine import AuditEngine
from .core.logging_config import get_logger
from .core.policy import NetworkPolicy
from .core.rules import FirewallRule
from .devices.linux_iptables import LinuxIptables
from .enforcement.engine import EnforcementEngine

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
    console.print("    policy_file    Path to policy file (YAML or JSON) [required]")
    console.print("    devices_file   Path to devices configuration file [required]")
    console.print("  [bold]Options:[/bold]")
    console.print(
        "    --output-format TEXT    Output format: text, json, html [default: text]"
    )
    console.print("    --output-file PATH      Output file path")
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
    policy_file: Path = typer.Argument(..., help="Path to policy file (YAML or JSON)"),
    devices_file: Path = typer.Argument(..., help="Path to devices configuration file"),
    output_format: str = typer.Option("text", help="Output format: text, json, html"),
    output_file: Optional[Path] = typer.Option(None, help="Output file path"),
    verbose: int = typer.Option(
        0, "-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)"
    ),
):
    """Audit devices against a network security policy."""

    # Setup logging based on verbosity
    from .core.logging_config import setup_logging

    setup_logging(min(verbose, 2))

    console.print("[bold blue]Starting Policy Audit...[/bold blue]")

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

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing devices...", total=None)

        try:
            result = asyncio.run(audit_engine.audit_policy(policy, devices))
            progress.update(task, completed=True, description="✓ Audit completed")
            logger.info("Audit completed successfully")
        except Exception as e:
            console.print(f"[red]Error during audit: {e}[/red]")
            logger.error(f"Error during audit: {e}")
            raise typer.Exit(1)

    # Generate report
    report = audit_engine.generate_audit_report(result, output_format)

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
    policy_file: Path = typer.Argument(..., help="Path to policy file (YAML or JSON)"),
    devices_file: Path = typer.Argument(..., help="Path to devices configuration file"),
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

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Enforcing policy...", total=None)

        try:
            result = asyncio.run(
                enforcement_engine.enforce_policy(policy, devices, dry_run)
            )
            progress.update(task, completed=True, description="✓ Enforcement completed")
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
            device = LinuxIptables(
                host=device_config["host"],
                username=device_config["username"],
                password=device_config.get("password"),
                private_key=device_config.get("private_key"),
                private_key_passphrase=device_config.get("private_key_passphrase"),
                port=device_config.get("port", 22),
                sudo_password=device_config.get("sudo_password"),
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
