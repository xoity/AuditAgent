"""
Command-line interface for AuditAgent.
"""

import asyncio
import json
import os
import time
from pathlib import Path
from typing import List, Optional

import requests
import typer
import yaml
from rich.console import Console
from rich.table import Table

from .audit.engine import AuditEngine
from .core.logging_config import get_logger
from .core.policy import NetworkPolicy
from .core.rules import FirewallRule
from .core.token import TokenManager
from .devices.linux_iptables import LinuxIptables
from .enforcement.engine import EnforcementEngine
from .enforcement.remediation import RemediationStrategy

console = Console()

# Import AI modules (optional dependency)
try:
    from .ai import AIConfig, AIProvider, AIRemediationEngine

    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    AIConfig = None  # type: ignore
    AIProvider = None  # type: ignore
    AIRemediationEngine = None  # type: ignore


def version_callback(value: bool):
    if value:
        console.print("AuditAgent version 0.1.0")
        raise typer.Exit()


def help_callback(ctx: typer.Context, _param: typer.CallbackParam, value: bool):
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
    console.print(
        "    file1    Path to policy or devices file (YAML or JSON) [required]"
    )
    console.print(
        "    file2    Path to devices or policy file (YAML or JSON) [required]"
    )
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
    console.print("  python -m audit_agent.cli auto-generate policy.yaml devices.yaml")
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
token_manager = TokenManager()


@app.command()
def login(
    api_url: str = typer.Option(
        "http://localhost:8000",
        "--api-url",
        help="API server URL"
    ),
):
    """
    Authenticate with AuditAgent UI.
    
    This will open a browser for you to log in and authorize this CLI instance.
    Similar to 'semgrep login'.
    """
    console.print("[bold blue]🔐 AuditAgent Login[/bold blue]\n")
    
    # Step 1: Request device code
    console.print("Requesting authentication code...")
    
    try:
        response = requests.post(f"{api_url}/api/device/code", timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        console.print(f"[red]✗ Failed to connect to API: {e}[/red]")
        console.print(f"[red]  Make sure the AuditAgent UI is running at {api_url}[/red]")
        raise typer.Exit(1)
    
    device_code = data["device_code"]
    user_code = data["user_code"]
    verification_uri = data["verification_uri"]
    expires_in = data["expires_in"]
    interval = data.get("interval", 5)
    
    # Step 2: Display instructions
    console.print("\n[bold yellow]To authenticate:[/bold yellow]")
    console.print(f"  1. Open this URL in your browser: [cyan]{verification_uri}[/cyan]")
    console.print(f"  2. Enter this code: [bold green]{user_code}[/bold green]")
    console.print(f"\n[dim]Waiting for you to complete authentication...[/dim]")
    console.print(f"[dim]Code expires in {expires_in} seconds[/dim]\n")
    
    # Try to open browser automatically
    try:
        import webbrowser
        webbrowser.open(verification_uri)
        console.print("[dim]✓ Opened browser automatically[/dim]\n")
    except Exception:
        pass
    
    # Step 3: Poll for token
    start_time = time.time()
    
    with console.status("[bold green]Waiting for authorization...") as status:
        while True:
            elapsed = time.time() - start_time
            
            if elapsed > expires_in:
                console.print("[red]✗ Authentication timed out. Please try again.[/red]")
                raise typer.Exit(1)
            
            time.sleep(interval)
            
            try:
                token_response = requests.post(
                    f"{api_url}/api/device/token",
                    json={"device_code": device_code},
                    timeout=10
                )
                
                if token_response.status_code == 200:
                    token_data = token_response.json()
                    access_token = token_data["access_token"]
                    
                    # Save token
                    token_manager.save_token(access_token, api_url)
                    
                    console.print("\n[bold green]✓ Authentication successful![/bold green]")
                    console.print(f"[dim]Token saved to {token_manager.config_file}[/dim]\n")
                    console.print("[bold]You can now use AuditAgent CLI with the UI.[/bold]")
                    return
                elif token_response.status_code == 400:
                    error_data = token_response.json()
                    error = error_data.get("error", "unknown")
                    
                    if error == "expired_token":
                        console.print("[red]✗ Authentication code expired. Please try again.[/red]")
                        raise typer.Exit(1)
                    elif error == "invalid_request":
                        console.print("[red]✗ Invalid request. Please try again.[/red]")
                        raise typer.Exit(1)
                    # authorization_pending - continue polling
                else:
                    console.print(f"[red]✗ Unexpected response: {token_response.status_code}[/red]")
                    raise typer.Exit(1)
                    
            except requests.RequestException as e:
                console.print(f"[red]✗ Connection error: {e}[/red]")
                raise typer.Exit(1)


@app.command()
def logout():
    """Remove stored authentication token."""
    console.print("[bold blue]Logging out...[/bold blue]")
    token_manager.clear_token()
    console.print("[green]✓ Logged out successfully[/green]")


@app.command()
def whoami(
    api_url: str = typer.Option(
        None,
        "--api-url",
        help="API server URL (defaults to saved URL)"
    ),
):
    """Display current authentication status."""
    token = token_manager.get_token()
    saved_api_url = token_manager.get_api_url()
    
    if api_url is None:
        api_url = saved_api_url
    
    if not token:
        console.print("[yellow]Not authenticated. Run 'auditagent login' to authenticate.[/yellow]")
        raise typer.Exit(1)
    
    console.print(f"[bold]Authentication Status:[/bold]")
    console.print(f"  API URL: [cyan]{api_url}[/cyan]")
    console.print(f"  Token: [green]{'*' * 20}{token[-8:]}[/green]")
    console.print(f"  Config: [dim]{token_manager.config_file}[/dim]")


# we need to implement this method for later
@app.callback()
def main_callback(
    show_help: bool = typer.Option(
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
    pass  ## noooooooooooooooooooooooooooooooS


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
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Non-interactive mode (no prompts, fail if credentials needed)",
    ),
    ssh_agent: bool = typer.Option(
        True, "--ssh-agent/--no-ssh-agent", help="Enable or disable SSH agent usage"
    ),
    verbose: int = typer.Option(
        0, "-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)"
    ),
):
    """Audit devices against a network security policy."""

    # Setup logging based on verbosity
    from .core.credentials import credential_manager
    from .core.logging_config import setup_logging

    setup_logging(min(verbose, 2))

    # Configure credential manager
    credential_manager.set_non_interactive(
        non_interactive or os.environ.get("AUDIT_AGENT_NONINTERACTIVE") == "1"
    )
    credential_manager.set_allow_ssh_agent(ssh_agent)

    console.print("[bold blue]Starting Policy Audit...[/bold blue]")

    # Auto-detect file types
    policy_file, devices_file = auto_detect_file_types(file1, file2)

    # Load policy
    try:
        policy = load_policy(policy_file)
        console.print(f"✓ Loaded policy: {policy.metadata.name}")
        logger.info("Loaded policy: %s", policy.metadata.name)
    except Exception as e:
        console.print(f"[red]Error loading policy: {e}[/red]")
        logger.error("Error loading policy: %s", e)
        raise typer.Exit(1)

    # Load devices
    try:
        devices = load_devices(devices_file)
        console.print(f"✓ Loaded {len(devices)} devices")
        logger.info("Loaded %s devices", len(devices))
    except Exception as e:
        console.print(f"[red]Error loading devices: {e}[/red]")
        logger.error("Error loading devices: %s", e)
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
        logger.error("Error during audit: %s", e)
        raise typer.Exit(1)

    # Generate report
    report = audit_engine.generate_audit_report(result, output_format, full_report)

    if output_file:
        output_file.write_text(report)
        console.print(f"✓ Report saved to {output_file}")
        logger.info("Report saved to %s", output_file)
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
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Fail instead of prompting for credentials (can also set AUDIT_AGENT_NONINTERACTIVE=1)",
    ),
    ssh_agent: Optional[bool] = typer.Option(
        None,
        "--ssh-agent/--no-ssh-agent",
        help="Enable/disable SSH agent usage (default: auto-detect)",
    ),
):
    """Enforce a network security policy on devices."""

    # Setup logging based on verbosity
    from .core.logging_config import setup_logging

    setup_logging(min(verbose, 2))

    # Configure credential manager
    from .core.credentials import credential_manager

    if non_interactive or os.environ.get("AUDIT_AGENT_NONINTERACTIVE") == "1":
        credential_manager.set_non_interactive(True)

    if ssh_agent is not None:
        credential_manager.set_allow_ssh_agent(ssh_agent)

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
        logger.info("Loaded policy: %s", policy.metadata.name)
        logger.info("Loaded %s devices", len(devices))
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        logger.error("Error loading configuration: %s", e)
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
        logger.error("Error during enforcement: %s", e)
        raise typer.Exit(1)

    # Generate report
    report = enforcement_engine.generate_enforcement_report(result, output_format)

    if output_file:
        output_file.write_text(report)
        console.print(f"✓ Report saved to {output_file}")
        logger.info("Report saved to %s", output_file)
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
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Fail instead of prompting for credentials (can also set AUDIT_AGENT_NONINTERACTIVE=1)",
    ),
    ssh_agent: Optional[bool] = typer.Option(
        None,
        "--ssh-agent/--no-ssh-agent",
        help="Enable/disable SSH agent usage (default: auto-detect)",
    ),
):
    """Automatically remediate compliance issues using smart enforcement."""

    # Setup logging based on verbosity
    from .core.logging_config import setup_logging

    setup_logging(min(verbose, 2))

    # Configure credential manager
    from .core.credentials import credential_manager

    if non_interactive or os.environ.get("AUDIT_AGENT_NONINTERACTIVE") == "1":
        credential_manager.set_non_interactive(True)

    if ssh_agent is not None:
        credential_manager.set_allow_ssh_agent(ssh_agent)

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
        logger.info("Loaded policy: %s", policy.metadata.name)
        logger.info("Loaded %s devices", len(devices))
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        logger.error("Error loading configuration: %s", e)
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
        logger.error("Error during automated remediation: %s", e)
        raise typer.Exit(1)

    # Generate report
    report = enforcement_engine.generate_enhanced_enforcement_report(
        result, output_format
    )

    if output_file:
        output_file.write_text(report)
        console.print(f"✓ Report saved to {output_file}")
        logger.info("Report saved to %s", output_file)
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
        None,
        help="Output file for remediation policy (default: remediation-policy.yaml)",
    ),
    include_commands: bool = typer.Option(
        True,
        "--include-commands/--no-include-commands",
        help="Include suggested iptables commands in output",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Non-interactive mode (no prompts, fail if credentials needed)",
    ),
    ssh_agent: bool = typer.Option(
        True, "--ssh-agent/--no-ssh-agent", help="Enable or disable SSH agent usage"
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
    from .core.credentials import credential_manager
    from .core.logging_config import setup_logging

    setup_logging(min(verbose, 2))

    # Configure credential manager
    credential_manager.set_non_interactive(
        non_interactive or os.environ.get("AUDIT_AGENT_NONINTERACTIVE") == "1"
    )
    credential_manager.set_allow_ssh_agent(ssh_agent)

    console.print("[bold cyan]🔧 Auto-Generating Remediation Policy...[/bold cyan]\n")

    # Auto-detect file types
    policy_file, devices_file = auto_detect_file_types(file1, file2)

    # Load policy
    try:
        policy = load_policy(policy_file)
        console.print(f"✓ Loaded policy: {policy.metadata.name}")
        logger.info("Loaded policy: %s", policy.metadata.name)
    except Exception as e:
        console.print(f"[red]Error loading policy: {e}[/red]")
        logger.error("Error loading policy: %s", e)
        raise typer.Exit(1)

    # Load devices
    try:
        devices = load_devices(devices_file)
        console.print(f"✓ Loaded {len(devices)} devices")
        logger.info("Loaded %s devices", len(devices))
    except Exception as e:
        console.print(f"[red]Error loading devices: {e}[/red]")
        logger.error("Error loading devices: %s", e)
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
        logger.error("Error during audit: %s", e)
        raise typer.Exit(1)

    # Check if there are any issues
    if result.total_issues == 0:
        console.print(
            "[green]✓ No compliance issues found! Your devices are compliant.[/green]"
        )
        console.print("[green]  No remediation policy needed.[/green]")
        return

    console.print(f"[yellow]Found {result.total_issues} compliance issues[/yellow]")
    console.print(f"  • Critical: {len(result.get_critical_issues())}")
    console.print(f"  • High: {len(result.get_high_issues())}")

    # Get medium and low issues manually
    all_issues = []
    for device_result in result.device_results:
        all_issues.extend(device_result.issues)
    medium_issues = [
        i for i in all_issues if hasattr(i, "severity") and i.severity == "medium"
    ]
    low_issues = [
        i for i in all_issues if hasattr(i, "severity") and i.severity == "low"
    ]

    console.print(f"  • Medium: {len(medium_issues)}")
    console.print(f"  • Low: {len(low_issues)}\n")

    # Generate remediation policy
    console.print("[bold]Step 2:[/bold] Generating remediation policy...")

    remediation_policy = NetworkPolicy(f"{policy.metadata.name}-remediation")
    remediation_policy.metadata.description = (
        f"Auto-generated remediation policy for {policy.metadata.name}"
    )
    remediation_policy.metadata.author = "AuditAgent Auto-Generate"

    # Track what we're adding
    rules_added = 0
    devices_covered = set()

    # Process each device's issues
    for device_result in result.device_results:
        if not device_result.issues:
            continue

        device_name = (
            str(device_result.device) if hasattr(device_result, "device") else "unknown"
        )
        devices_covered.add(device_name)

        for issue in device_result.issues:
            # Check if this is a missing rule issue
            if (
                "missing from device" in issue.description.lower()
                or "required" in issue.description.lower()
            ):
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
                        rule_exists = any(
                            r.name == original_rule.name
                            for r in remediation_policy.firewall_rules
                        )
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

    # Generate suggested commands if requested
    if include_commands and remediation_policy.firewall_rules:
        commands_file = output_file.parent / f"{output_file.stem}-commands.sh"
        console.print(
            f"[bold]Step 4:[/bold] Generating suggested iptables commands to {commands_file}..."
        )

        try:
            commands_content = [
                "#!/bin/bash",
                "# Generated iptables commands for remediation policy",
                f"# Policy: {remediation_policy.metadata.name}",
            ]
            if remediation_policy.metadata.created_date:
                commands_content.append(
                    f"# Generated: {remediation_policy.metadata.created_date}"
                )
            commands_content.extend(
                [
                    "",
                    "# WARNING: Review these commands before executing!",
                    "# These are suggestions based on the remediation policy.",
                    "",
                ]
            )

            # Group rules by device
            device_rules = {}
            for rule in remediation_policy.firewall_rules:
                # For auto-generated policies, we can organize by rule characteristics
                # In a real implementation, you'd track which device each rule applies to
                device_key = "all-devices"
                if device_key not in device_rules:
                    device_rules[device_key] = []
                device_rules[device_key].append(rule)

            # Generate commands for each device
            for device_name, rules in device_rules.items():
                commands_content.append(f"# Commands for: {device_name}")
                commands_content.append("")

                for rule in rules:
                    commands_content.append(f"# Rule: {rule.name}")
                    if rule.description:
                        commands_content.append(f"# Description: {rule.description}")

                    # Generate iptables commands for this rule
                    iptables_cmds = firewall_rule_to_iptables(rule)
                    for cmd in iptables_cmds:
                        commands_content.append(cmd)

                    commands_content.append("")

            # Add save command
            commands_content.append("# Save iptables rules (optional)")
            commands_content.append("# iptables-save > /etc/iptables/rules.v4")
            commands_content.append("")

            commands_file.write_text("\n".join(commands_content))
            console.print(f"✓ Suggested commands saved to {commands_file}\n")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not generate commands: {e}[/yellow]")

    # Show what to do next
    console.print("[bold green]✓ Auto-Generation Complete![/bold green]\n")
    console.print("[bold cyan]Next Steps:[/bold cyan]")
    console.print(f"  1. Review the remediation policy: {output_file}")
    if include_commands:
        console.print(
            f"  2. Review suggested commands: {output_file.parent / f'{output_file.stem}-commands.sh'}"
        )
        console.print("  3. Test with dry-run first:")
    else:
        console.print("  2. Test with dry-run first:")
    console.print(
        f"     [dim]audit-agent enforce --dry-run {output_file} {devices_file}[/dim]"
    )
    if include_commands:
        console.print("  4. Apply the fixes:")
    else:
        console.print("  3. Apply the fixes:")
    console.print(
        f"     [dim]audit-agent enforce --no-dry-run {output_file} {devices_file}[/dim]"
    )
    if include_commands:
        console.print("  5. Or use auto-remediate:")
    else:
        console.print("  4. Or use auto-remediate:")
    console.print(
        f"     [dim]audit-agent auto-remediate {output_file} {devices_file}[/dim]\n"
    )

    # Show policy summary
    console.print("[bold]Remediation Policy Summary:[/bold]")
    display_policy_summary(remediation_policy)


@app.command()
def create_example(
    output_file: Path = typer.Argument(..., help="Output file path for example policy"),
    output_format: str = typer.Option("yaml", help="Output format: yaml, json"),
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
    if output_format.lower() == "yaml":
        content = policy.export_to_yaml()
    else:
        content = policy.export_to_json()

    output_file.write_text(content)
    console.print(f"✓ Example policy created: {output_file}")

    # Show summary
    display_policy_summary(policy)


@app.command(name="ai-remediate")
def ai_remediate(
    policy_file: Path = typer.Argument(..., help="Path to policy file (YAML or JSON)"),
    devices_file: Path = typer.Argument(..., help="Path to devices configuration file"),
    output_file: Path = typer.Option(
        None, "--output", "-o", help="Output file path for remediation policy"
    ),
    provider: str = typer.Option(
        None, "--provider", "-p", help="AI provider: google, openai, azure_openai"
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Apply the remediation policy after generation"
    ),
    max_iterations: int = typer.Option(
        2, "--max-iterations", help="Maximum AI refinement iterations"
    ),
    verbose: int = typer.Option(
        0, "-v", "--verbose", count=True, help="Increase verbosity (-v, -vv)"
    ),
):
    """
    AI-powered automatic remediation using Google AI Studio or OpenAI.

    This command:
    1. Audits devices against the policy
    2. Uses AI to analyze compliance issues
    3. Generates a remediation policy to achieve 100% compliance
    4. Optionally applies the remediation policy

    Setup:
    - Google AI Studio: Set GOOGLE_AI_API_KEY environment variable
    - OpenAI: Set OPENAI_API_KEY environment variable
    - Or configure in ~/.audit-agent/config.yaml
    """
    if not AI_AVAILABLE:
        console.print(
            "[red]✗ AI integration not available. Install with: pip install google-generativeai openai[/red]"
        )
        raise typer.Exit(1)

    # Configure logging
    if verbose == 1:
        os.environ["LOG_LEVEL"] = "INFO"
    elif verbose >= 2:
        os.environ["LOG_LEVEL"] = "DEBUG"

    console.print("[bold blue]AI-Powered Remediation[/bold blue]\n")

    # Load configuration
    try:
        ai_config = AIConfig.load_from_file()
    except Exception as e:
        console.print(f"[red]✗ Failed to load AI config: {e}[/red]")
        console.print(
            "\n[yellow]Set GOOGLE_AI_API_KEY or OPENAI_API_KEY environment variable[/yellow]"
        )
        console.print(
            "[yellow]Or create ~/.audit-agent/config.yaml with your API keys[/yellow]"
        )
        raise typer.Exit(1)

    # Validate provider configuration
    try:
        selected_provider = None
        if provider:
            selected_provider = AIProvider(provider.lower())
        ai_config.get_provider_config(selected_provider)
    except ValueError as e:
        console.print(f"[red]✗ {e}[/red]")
        console.print("\n[yellow]Available providers:[/yellow]")
        console.print("  • google (Google AI Studio / Gemini)")
        console.print("  • openai (OpenAI GPT)")
        console.print("  • azure_openai (Azure OpenAI)")
        raise typer.Exit(1)

    # Load policy and devices
    console.print(f"Loading policy from {policy_file}...")
    policy = load_policy(policy_file)

    console.print(f"Loading devices from {devices_file}...")
    devices = load_devices(devices_file)

    if not devices:
        console.print("[red]✗ No devices found in devices file[/red]")
        raise typer.Exit(1)

    console.print(f"✓ Loaded {len(devices)} device(s)\n")

    # Step 1: Initial Audit
    console.print("[bold]Step 1: Running initial audit...[/bold]")
    audit_engine = AuditEngine()
    original_result = asyncio.run(audit_engine.audit_policy(policy, devices))

    console.print(f"  Compliance: {original_result.overall_compliance_percentage:.1f}%")
    console.print(f"  Total Issues: {original_result.total_issues}")

    if original_result.is_compliant:
        console.print("\n[green]✓ Policy is already 100% compliant![/green]")
        raise typer.Exit(0)

    # Show issues by severity
    console.print("\n  Issues by severity:")
    for severity in ["critical", "high", "medium", "low"]:
        issues = original_result.get_issues_by_severity(severity)
        if issues:
            console.print(f"    • {severity.upper()}: {len(issues)}")

    # Step 2: AI Analysis and Generation
    console.print("\n[bold]Step 2: Generating AI remediation policy...[/bold]")
    ai_engine = AIRemediationEngine(ai_config)

    try:
        remediation_yaml, final_result = ai_engine.generate_and_validate(
            audit_result=original_result,
            original_policy=policy,
            devices=devices,
            provider=selected_provider,
            max_iterations=max_iterations,
        )

        # Check if policy is already correct (all issues are missing_rule)
        all_missing = all(
            issue.issue_type == "missing_rule"
            for device_result in original_result.device_results
            for issue in device_result.issues
        )

        if all_missing and original_result.total_issues > 0:
            console.print(
                "[yellow]ℹ  Policy is already correct - all issues are missing rules on the device.[/yellow]"
            )
            console.print(
                "[yellow]   The remediation output is the original policy.[/yellow]"
            )
            console.print(
                "[yellow]   Run with --apply to ENFORCE these rules on the device.[/yellow]"
            )

    except Exception as e:
        console.print(f"\n[red]✗ AI remediation failed: {e}[/red]")
        logger.exception("AI remediation error")
        raise typer.Exit(1)

    # Step 3: Display Results
    console.print("\n[bold]Step 3: Remediation Results[/bold]")
    console.print(
        f"  Final Compliance: {final_result.overall_compliance_percentage:.1f}%"
    )
    console.print(f"  Remaining Issues: {final_result.total_issues}")

    compliance_improvement = (
        final_result.overall_compliance_percentage
        - original_result.overall_compliance_percentage
    )
    issues_fixed = original_result.total_issues - final_result.total_issues

    console.print("\n  [bold]Improvement:[/bold]")
    console.print(f"    • Compliance: {compliance_improvement:+.1f}%")
    console.print(f"    • Issues Fixed: {issues_fixed}")

    if final_result.is_compliant:
        console.print("\n[green]✓ Successfully achieved 100% compliance![/green]")
    else:
        console.print("\n[yellow]⚠ Partial remediation - some issues remain[/yellow]")

    # Save remediation policy
    if output_file is None:
        output_file = (
            policy_file.parent
            / f"{policy_file.stem}-ai-remediation{policy_file.suffix}"
        )

    ai_engine.save_remediation_policy(remediation_yaml, output_file)
    console.print(f"\n[green]✓ Remediation policy saved to: {output_file}[/green]")

    # Generate summary report
    summary = ai_engine.generate_summary_report(original_result, final_result)
    summary_file = output_file.parent / f"{output_file.stem}-summary.md"
    summary_file.write_text(summary)
    console.print(f"[green]✓ Summary report saved to: {summary_file}[/green]")

    # Step 4: Apply if requested
    if apply:
        console.print("\n[bold]Step 4: Applying remediation policy...[/bold]")

        # Load the remediation policy
        remediation_policy = NetworkPolicy.from_yaml(remediation_yaml)

        # Apply enforcement
        enforcement_engine = EnforcementEngine()
        enforcement_result = asyncio.run(
            enforcement_engine.enforce_policy(
                remediation_policy, devices, dry_run=False
            )
        )

        # Display enforcement results
        console.print(
            f"\n  Actions Executed: {enforcement_result.total_actions_executed}"
        )
        console.print(f"  Successful: {enforcement_result.total_actions_successful}")
        console.print(f"  Failed: {enforcement_result.total_actions_failed}")

        if enforcement_result.is_successful:
            console.print("\n[green]✓ Remediation applied successfully![/green]")
        else:
            console.print(
                "\n[yellow]⚠ Some enforcement actions failed. Check logs for details.[/yellow]"
            )
    else:
        console.print("\n[bold]Next Steps:[/bold]")
        console.print(f"  1. Review the remediation policy: {output_file}")
        console.print(f"  2. Review the summary report: {summary_file}")
        console.print("  3. Apply the remediation:")
        console.print(
            f"     [dim]audit-agent ai-remediate {policy_file} {devices_file} --apply[/dim]"
        )
        console.print("     or")
        console.print(
            f"     [dim]audit-agent enforce --no-dry-run {output_file} {devices_file}[/dim]"
        )


def firewall_rule_to_iptables(rule: FirewallRule) -> List[str]:
    """Convert a firewall rule to iptables command(s)."""
    commands = []

    # Determine chain based on direction
    chain = "INPUT" if rule.direction.value == "inbound" else "OUTPUT"

    # Determine action
    action = "ACCEPT" if rule.action.value == "allow" else "DROP"

    # Build base command
    cmd_parts = ["iptables", "-A", chain]

    # Protocol
    if rule.protocol and rule.protocol.name != "any":
        cmd_parts.extend(["-p", rule.protocol.name])

    # Helper to get IP string (handles both IPAddress and IPRange)
    def ip_to_str(ip):
        if hasattr(ip, "cidr"):
            return ip.cidr
        elif hasattr(ip, "address"):
            return ip.address
        return str(ip)

    # Source IPs
    if rule.source_ips:
        for source_ip in rule.source_ips:
            cmd = cmd_parts.copy()
            cmd.extend(["-s", ip_to_str(source_ip)])

            # Destination IPs
            if rule.destination_ips:
                for dest_ip in rule.destination_ips:
                    dest_cmd = cmd.copy()
                    dest_cmd.extend(["-d", ip_to_str(dest_ip)])

                    # Destination ports
                    if rule.destination_ports:
                        for port in rule.destination_ports:
                            port_cmd = dest_cmd.copy()
                            if port.number:
                                port_cmd.extend(["--dport", str(port.number)])
                            elif port.range_start and port.range_end:
                                port_cmd.extend(
                                    ["--dport", f"{port.range_start}:{port.range_end}"]
                                )

                            # Add logging if enabled
                            if rule.log_traffic:
                                log_cmd = port_cmd.copy()
                                log_cmd[2] = "LOG"
                                log_cmd.extend(["--log-prefix", f"[{rule.name}] "])
                                commands.append(" ".join(log_cmd))

                            port_cmd.extend(["-j", action])
                            commands.append(" ".join(port_cmd))
                    else:
                        # No ports specified
                        if rule.log_traffic:
                            log_cmd = dest_cmd.copy()
                            log_cmd[2] = "LOG"
                            log_cmd.extend(["--log-prefix", f"[{rule.name}] "])
                            commands.append(" ".join(log_cmd))

                        dest_cmd.extend(["-j", action])
                        commands.append(" ".join(dest_cmd))
            else:
                # No destination IPs, add rule for source only
                if rule.destination_ports:
                    for port in rule.destination_ports:
                        port_cmd = cmd.copy()
                        if port.number:
                            port_cmd.extend(["--dport", str(port.number)])
                        elif port.range_start and port.range_end:
                            port_cmd.extend(
                                ["--dport", f"{port.range_start}:{port.range_end}"]
                            )

                        if rule.log_traffic:
                            log_cmd = port_cmd.copy()
                            log_cmd[2] = "LOG"
                            log_cmd.extend(["--log-prefix", f"[{rule.name}] "])
                            commands.append(" ".join(log_cmd))

                        port_cmd.extend(["-j", action])
                        commands.append(" ".join(port_cmd))
                else:
                    if rule.log_traffic:
                        log_cmd = cmd.copy()
                        log_cmd[2] = "LOG"
                        log_cmd.extend(["--log-prefix", f"[{rule.name}] "])
                        commands.append(" ".join(log_cmd))

                    cmd.extend(["-j", action])
                    commands.append(" ".join(cmd))
    else:
        # No source IPs specified, create rule for any source
        if rule.destination_ips:
            for dest_ip in rule.destination_ips:
                dest_cmd = cmd_parts.copy()
                dest_cmd.extend(["-d", ip_to_str(dest_ip)])

                if rule.destination_ports:
                    for port in rule.destination_ports:
                        port_cmd = dest_cmd.copy()
                        if port.number:
                            port_cmd.extend(["--dport", str(port.number)])
                        elif port.range_start and port.range_end:
                            port_cmd.extend(
                                ["--dport", f"{port.range_start}:{port.range_end}"]
                            )

                        if rule.log_traffic:
                            log_cmd = port_cmd.copy()
                            log_cmd[2] = "LOG"
                            log_cmd.extend(["--log-prefix", f"[{rule.name}] "])
                            commands.append(" ".join(log_cmd))

                        port_cmd.extend(["-j", action])
                        commands.append(" ".join(port_cmd))
                else:
                    if rule.log_traffic:
                        log_cmd = dest_cmd.copy()
                        log_cmd[2] = "LOG"
                        log_cmd.extend(["--log-prefix", f"[{rule.name}] "])
                        commands.append(" ".join(log_cmd))

                    dest_cmd.extend(["-j", action])
                    commands.append(" ".join(dest_cmd))
        else:
            # Simple rule with no IPs
            if rule.destination_ports:
                for port in rule.destination_ports:
                    port_cmd = cmd_parts.copy()
                    if port.number:
                        port_cmd.extend(["--dport", str(port.number)])
                    elif port.range_start and port.range_end:
                        port_cmd.extend(
                            ["--dport", f"{port.range_start}:{port.range_end}"]
                        )

                    if rule.log_traffic:
                        log_cmd = port_cmd.copy()
                        log_cmd[2] = "LOG"
                        log_cmd.extend(["--log-prefix", f"[{rule.name}] "])
                        commands.append(" ".join(log_cmd))

                    port_cmd.extend(["-j", action])
                    commands.append(" ".join(port_cmd))
            else:
                if rule.log_traffic:
                    log_cmd = cmd_parts.copy()
                    log_cmd[2] = "LOG"
                    log_cmd.extend(["--log-prefix", f"[{rule.name}] "])
                    commands.append(" ".join(log_cmd))

                cmd_parts.extend(["-j", action])
                commands.append(" ".join(cmd_parts))

    return commands if commands else [" ".join(cmd_parts + ["-j", action])]


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
    logger.debug("Auto-detecting file types for: %s and %s", file1, file2)

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
        logger.debug("Detected: %s = policy, %s = devices", file1, file2)
        return file1, file2
    elif is_policy_file(file2) and is_devices_file(file1):
        logger.debug("Detected: %s = policy, %s = devices", file2, file1)
        return file2, file1
    else:
        # Fallback to original order if detection fails
        logger.warning("Could not auto-detect file types, using original order")
        return file1, file2


def load_devices(devices_file: Path) -> List:
    """Load device configurations from file."""
    logger.debug("Loading devices from: %s", devices_file)
    content = devices_file.read_text()
    logger.debug("Device file content: %s", content)

    if devices_file.suffix.lower() in [".yaml", ".yml"]:
        devices_config = yaml.safe_load(content)
    elif devices_file.suffix.lower() == ".json":
        devices_config = json.loads(content)
    else:
        raise ValueError(f"Unsupported devices file format: {devices_file.suffix}")

    logger.debug("Parsed device config: %s", devices_config)
    devices = []

    for device_config in devices_config.get("devices", []):
        logger.debug("Processing device config: %s", device_config)
        device_type = device_config.get("type", "").lower()
        logger.debug("Device type: %s", device_type)

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
            logger.debug("Created device: %s", device)
        else:
            console.print(
                f"[yellow]Warning: Unsupported device type: {device_type}[/yellow]"
            )
            console.print("[yellow]Supported types: linux_iptables[/yellow]")

    logger.debug("Total devices loaded: %s", len(devices))
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
