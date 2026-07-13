"""
Linux iptables firewall device implementation.
"""

import re
import shlex
from typing import List, Optional

from ..core.credentials import credential_manager
from ..core.logging_config import get_logger
from ..core.objects import IPAddress, IPRange
from ..core.rules import Action, BaseRule, FirewallRule
from .base import (
    CommandResult,
    ConfigurationItem,
    DeviceConfiguration,
    DeviceConnection,
    DeviceInfo,
    FirewallDevice,
)

logger = get_logger(__name__)


def firewall_rule_to_commands(rule: FirewallRule) -> List[str]:
    """Convert a FirewallRule to iptables command strings."""
    if rule.direction.value == "bidirectional":
        return _build_iptables_rule(rule, "INPUT") + _build_iptables_rule(
            rule, "OUTPUT"
        )
    chain = "INPUT" if rule.direction.value == "inbound" else "OUTPUT"
    return _build_iptables_rule(rule, chain)


def _build_iptables_rule(rule: FirewallRule, chain: str) -> List[str]:
    """Build iptables rule for a specific chain. Expands multiple IPs/ports into separate rules."""
    import itertools

    base_parts = ["iptables", "-A", chain]
    if rule.protocol and rule.protocol.name != "any":
        base_parts.extend(["-p", rule.protocol.name])

    def _ip_flag(ip_val, flag: str) -> List[str]:
        if isinstance(ip_val, IPAddress):
            return [flag, ip_val.address]
        elif isinstance(ip_val, IPRange):
            return [flag, ip_val.cidr]
        return []

    source_variants = [_ip_flag(ip, "-s") for ip in rule.source_ips] or [[]]
    dest_variants = [_ip_flag(ip, "-d") for ip in rule.destination_ips] or [[]]

    dport_variants: List[List[str]] = []
    if (
        rule.protocol
        and rule.protocol.name in ("tcp", "udp")
        and rule.destination_ports
    ):
        for port in rule.destination_ports:
            if port.is_single():
                dport_variants.append(["--dport", str(port.number)])
            elif port.is_range():
                dport_variants.append(
                    ["--dport", f"{port.range_start}:{port.range_end}"]
                )
    dport_variants = dport_variants or [[]]

    sport_variants: List[List[str]] = []
    if rule.protocol and rule.protocol.name in ("tcp", "udp") and rule.source_ports:
        for port in rule.source_ports:
            if port.is_single():
                sport_variants.append(["--sport", str(port.number)])
            elif port.is_range():
                sport_variants.append(
                    ["--sport", f"{port.range_start}:{port.range_end}"]
                )
    sport_variants = sport_variants or [[]]

    log_prefix = shlex.quote(f"[{rule.name or 'RULE'}] ")

    def _action_parts() -> List[str]:
        if rule.action == Action.ALLOW:
            return ["-j", "ACCEPT"]
        elif rule.action in (Action.DENY, Action.DROP):
            return ["-j", "DROP"]
        elif rule.action == Action.REJECT:
            return ["-j", "REJECT"]
        return []

    action_parts = _action_parts()

    commands: List[str] = []
    for s, d, dp, sp in itertools.product(
        source_variants, dest_variants, dport_variants, sport_variants
    ):
        match = base_parts + s + d + dp + sp

        if rule.log_traffic and action_parts:
            commands.append(" ".join(match + ["-j", "LOG", "--log-prefix", log_prefix]))
            commands.append(" ".join(match + action_parts))
        elif rule.log_traffic or rule.action == Action.LOG:
            commands.append(" ".join(match + ["-j", "LOG", "--log-prefix", log_prefix]))
        else:
            commands.append(" ".join(match + action_parts))

    return commands


class LinuxIptables(FirewallDevice):
    """Linux server with iptables firewall implementation."""

    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
    ):
        from .base import DeviceCredentials

        credentials = DeviceCredentials(
            username=username,
            password=password,
            private_key=private_key,
        )
        connection = DeviceConnection(
            host=host, port=port, protocol="ssh", credentials=credentials
        )
        super().__init__(connection)
        # Removed insecure sudo_password assignment
        self._ssh_client = None

    async def connect(self) -> bool:
        """Connect to the Linux server via SSH."""
        try:
            import paramiko

            # Validate required credentials
            if not self.connection.credentials.username:
                logger.error("SSH username is required")
                return False

            self._ssh_client = paramiko.SSHClient()
            # Load known hosts for secure host key verification
            self._ssh_client.load_system_host_keys()
            self._ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())

            connect_kwargs = {
                "hostname": self.connection.host,
                "port": self.connection.port or 22,
                "username": self.connection.credentials.username,
                "timeout": self.connection.timeout,
                "look_for_keys": True,  # Let paramiko try keys in ~/.ssh/
                "allow_agent": True,  # Let paramiko use SSH agent
            }

            # Try private key authentication first if specified
            if self.connection.credentials.private_key:
                key = credential_manager.load_private_key(
                    self.connection.credentials.private_key,
                    self.connection.credentials.username,
                    self.connection.host,
                )

                if key:
                    connect_kwargs["pkey"] = key
                    connect_kwargs["look_for_keys"] = False  # Don't look for other keys
                    logger.debug("Using specified private key for authentication")

                    try:
                        self._ssh_client.connect(**connect_kwargs)

                        # Test connection
                        stdin, stdout, stderr = self._ssh_client.exec_command(
                            "echo 'test'"
                        )
                        stdout.read()

                        self._connected = True
                        self._device_info = await self.get_device_info()

                        logger.info(
                            "Successfully connected to %s using private key",
                            self.connection.host,
                        )
                        return True

                    except Exception as e:
                        logger.debug("Private key authentication failed: %s", e)
                        # Create fresh SSH client for next attempt
                        self._ssh_client.close()
                        self._ssh_client = paramiko.SSHClient()
                        # Load known hosts for secure host key verification
                        self._ssh_client.load_system_host_keys()
                        self._ssh_client.set_missing_host_key_policy(
                            paramiko.RejectPolicy()
                        )
                else:
                    logger.warning(
                        "Could not load private key: %s",
                        self.connection.credentials.private_key,
                    )

            # Try password authentication if provided
            if self.connection.credentials.password:
                connect_kwargs["password"] = self.connection.credentials.password
                connect_kwargs["look_for_keys"] = (
                    False  # Don't look for keys when password provided
                )
                connect_kwargs["allow_agent"] = (
                    False  # Don't use agent when password provided
                )
                logger.debug("Using provided password for authentication")

                try:
                    self._ssh_client.connect(**connect_kwargs)

                    # Test connection
                    stdin, stdout, stderr = self._ssh_client.exec_command("echo 'test'")
                    stdout.read()

                    self._connected = True
                    self._device_info = await self.get_device_info()

                    logger.info(
                        "Successfully connected to %s using password",
                        self.connection.host,
                    )
                    return True

                except Exception as e:
                    logger.error("Password authentication failed: %s", e)
                    return False

            # Try default SSH authentication (agent + default keys)
            logger.debug("Trying default SSH authentication (agent + keys in ~/.ssh/)")
            try:
                # Reset connect_kwargs to default (with agent and keys)
                connect_kwargs = {
                    "hostname": self.connection.host,
                    "port": self.connection.port or 22,
                    "username": self.connection.credentials.username,
                    "timeout": self.connection.timeout,
                    "look_for_keys": True,
                    "allow_agent": True,
                }

                self._ssh_client.connect(**connect_kwargs)

                # Test connection
                stdin, stdout, stderr = self._ssh_client.exec_command("echo 'test'")
                stdout.read()

                self._connected = True
                self._device_info = await self.get_device_info()

                logger.info(
                    "Successfully connected to %s using default SSH authentication",
                    self.connection.host,
                )
                return True

            except Exception as e:
                logger.debug("Default SSH authentication failed: %s", e)

                # Last resort: prompt for password
                password = credential_manager.get_ssh_password(
                    self.connection.credentials.username, self.connection.host
                )

                if password:
                    try:
                        # Create fresh SSH client
                        self._ssh_client.close()
                        self._ssh_client = paramiko.SSHClient()
                        # Load known hosts for secure host key verification
                        self._ssh_client.load_system_host_keys()
                        self._ssh_client.set_missing_host_key_policy(
                            paramiko.RejectPolicy()
                        )

                        connect_kwargs = {
                            "hostname": self.connection.host,
                            "port": self.connection.port or 22,
                            "username": self.connection.credentials.username,
                            "timeout": self.connection.timeout,
                            "password": password,
                            "look_for_keys": False,
                            "allow_agent": False,
                        }

                        self._ssh_client.connect(**connect_kwargs)

                        # Test connection
                        stdin, stdout, stderr = self._ssh_client.exec_command(
                            "echo 'test'"
                        )
                        stdout.read()

                        self._connected = True
                        self._device_info = await self.get_device_info()

                        logger.info(
                            "Successfully connected to %s using prompted password",
                            self.connection.host,
                        )
                        return True

                    except Exception as pwd_error:
                        logger.error(
                            "Prompted password authentication failed: %s", pwd_error
                        )
                        return False
                else:
                    logger.error("No authentication method available")
                    return False

        except Exception as e:
            self._connected = False
            logger.error("Failed to connect to %s: %s", self.connection.host, e)
            return False

    async def disconnect(self) -> None:
        """Disconnect from the server."""
        if self._ssh_client:
            self._ssh_client.close()
            self._ssh_client = None
        self._connected = False

    async def execute_command(
        self, command: str, use_sudo: Optional[bool] = None
    ) -> CommandResult:
        """Execute a command on the Linux server."""
        if not self._ssh_client:
            return CommandResult(
                command=command,
                success=False,
                output="",
                error="Not connected to device",
                execution_time=0.0,
            )

        import time

        start_time = time.time()

        try:
            original_command = command

            # Validate command input to prevent obvious injection attempts
            # Check for dangerous command chaining or injection patterns
            dangerous_patterns = [";", "&&", "||", "|", "`", "$(", "\n", "\r"]
            # Allow pipe only for specific safe commands
            if any(pattern in command for pattern in dangerous_patterns):
                # Check if it's an allowed pattern (like iptables-save, base64 piping, etc)
                allowed_commands = [
                    "iptables-save",
                    "ip6tables-save",
                    "base64 -d",
                    "grep",
                    "awk",
                    "sed",
                    "sort",
                    "uniq",
                    "wc",
                    "cat /etc/",
                ]
                if not any(allowed in command for allowed in allowed_commands):
                    logger.warning(
                        "Potentially dangerous command detected: %s", command
                    )
                    # Still allow but log it - in production you might want to reject

            # Determine if sudo is needed
            if use_sudo is None:
                use_sudo = any(
                    cmd in command
                    for cmd in [
                        "iptables",
                        "ip6tables",
                        "iptables-save",
                        "iptables-restore",
                    ]
                )

            # Build the command
            shell_command = self._build_shell_command(command, use_sudo)

            # Try the simpler exec_command approach first (compatible with tests)
            try:
                stdin, stdout, stderr = self._ssh_client.exec_command(shell_command)

                # Read output
                stdout_data = stdout.read()
                stderr_data = stderr.read()
                exit_code = stdout.channel.recv_exit_status()

            except Exception as e:
                # If simple approach fails, try the channel-based approach
                logger.debug(
                    "Simple exec_command failed: %s, trying channel approach", e
                )
                transport = self._ssh_client.get_transport()
                if not transport:
                    raise Exception("No transport available")

                channel = transport.open_session()

                try:
                    # Set environment variables for better shell handling
                    try:
                        channel.set_environment_variable(
                            "DEBIAN_FRONTEND", "noninteractive"
                        )
                        channel.set_environment_variable("PYTHONUNBUFFERED", "1")
                    except Exception:
                        # Some SSH servers don't support environment variables
                        pass

                    # Execute the command
                    channel.exec_command(shell_command)

                    # Read output in a non-blocking way
                    stdout_data = b""
                    stderr_data = b""

                    while True:
                        if channel.recv_ready():
                            chunk = channel.recv(4096)
                            if chunk:
                                stdout_data += chunk

                        if channel.recv_stderr_ready():
                            chunk = channel.recv_stderr(4096)
                            if chunk:
                                stderr_data += chunk

                        if channel.exit_status_ready():
                            break

                        # Small sleep to prevent busy waiting
                        time.sleep(0.01)

                    # Get any remaining data
                    while channel.recv_ready():
                        chunk = channel.recv(4096)
                        if chunk:
                            stdout_data += chunk

                    while channel.recv_stderr_ready():
                        chunk = channel.recv_stderr(4096)
                        if chunk:
                            stderr_data += chunk

                    exit_code = channel.recv_exit_status()

                finally:
                    channel.close()

            execution_time = time.time() - start_time

            output = stdout_data.decode("utf-8", errors="replace")
            error = (
                stderr_data.decode("utf-8", errors="replace") if stderr_data else None
            )

            result = CommandResult(
                command=original_command,
                success=exit_code == 0,
                output=output,
                error=error,
                exit_code=exit_code,
                execution_time=execution_time,
            )

            logger.debug("Executing command: %s", original_command)
            logger.debug("Result: success=%s, exit_code=%s", result.success, exit_code)
            if result.error:
                logger.debug("Error: %s", result.error)

            return result

        except Exception as e:
            return CommandResult(
                command=command,
                success=False,
                output="",
                error=f"Command execution failed: {str(e)}",
                execution_time=time.time() - start_time
                if "start_time" in locals()
                else 0.0,
            )

    def _build_shell_command(self, command: str, use_sudo: bool = False) -> str:
        return f"set -e && {'sudo ' if use_sudo else ''}{command}"

    async def execute_commands_batch(
        self, commands: List[str], stop_on_error: bool = True
    ) -> List[CommandResult]:
        """Execute multiple commands in sequence"""
        results = []

        for command in commands:
            result = await self.execute_command(command)
            results.append(result)

            # Stop on first error if requested
            if stop_on_error and not result.success:
                logger.error(
                    "Stopping batch execution due to error in command: %s", command
                )
                break

        return results

    async def get_configuration(self) -> DeviceConfiguration:
        """Get the current iptables configuration."""
        import datetime

        # Get iptables rules
        ipv4_result = await self.execute_command("iptables-save")
        ipv6_result = await self.execute_command("ip6tables-save")

        raw_config = ""
        if ipv4_result.success:
            raw_config += "# IPv4 Rules\n" + ipv4_result.output + "\n"
        if ipv6_result.success:
            raw_config += "# IPv6 Rules\n" + ipv6_result.output + "\n"

        parsed_items = self.parse_configuration(raw_config)

        return DeviceConfiguration(
            device_info=self._device_info
            or DeviceInfo(
                hostname="unknown", vendor="linux", model="server", version="unknown"
            ),
            raw_config=raw_config,
            parsed_items=parsed_items,
            timestamp=datetime.datetime.now().isoformat(),
        )

    async def backup_configuration(self) -> str:
        """Snapshot IPv4 and IPv6 rules for transactional enforcement."""
        import json

        ipv4 = await self.execute_command("iptables-save")
        ipv6 = await self.execute_command("ip6tables-save")
        if not ipv4.success or not ipv6.success:
            errors = [result.error for result in (ipv4, ipv6) if not result.success]
            raise RuntimeError(
                "; ".join(error or "snapshot failed" for error in errors)
            )
        return json.dumps({"ipv4": ipv4.output, "ipv6": ipv6.output})

    async def restore_configuration(self, backup: str) -> CommandResult:
        """Restore snapshot created by backup_configuration."""
        import base64
        import json

        snapshots = json.loads(backup)
        results = []
        for family, command in (
            ("ipv4", "iptables-restore"),
            ("ipv6", "ip6tables-restore"),
        ):
            encoded = base64.b64encode(snapshots[family].encode()).decode()
            results.append(
                await self.execute_command(
                    f"printf '%s' '{encoded}' | base64 -d | sudo {command}",
                    use_sudo=False,
                )
            )
        success = all(result.success for result in results)
        return CommandResult(
            command="restore_configuration",
            success=success,
            output="Rollback snapshot restored" if success else "",
            error="; ".join(
                result.error or "restore failed"
                for result in results
                if not result.success
            )
            or None,
            execution_time=sum(result.execution_time for result in results),
        )

    async def get_device_info(self) -> DeviceInfo:
        """Get Linux server information."""
        hostname_result = await self.execute_command("hostname")
        os_result = await self.execute_command("cat /etc/os-release")
        kernel_result = await self.execute_command("uname -r")
        interfaces_result = await self.execute_command(
            "ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/:$//'"
        )

        hostname = (
            hostname_result.output.strip() if hostname_result.success else "unknown"
        )

        # Parse OS information
        os_output = os_result.output if os_result.success else ""
        version = "unknown"
        model = "server"

        if "VERSION=" in os_output:
            version_match = re.search(r'VERSION="([^"]+)"', os_output)
            if version_match:
                version = version_match.group(1)

        if "NAME=" in os_output:
            name_match = re.search(r'NAME="([^"]+)"', os_output)
            if name_match:
                model = name_match.group(1)

        kernel_version = (
            kernel_result.output.strip() if kernel_result.success else "unknown"
        )

        # Parse interfaces
        interfaces = []
        if interfaces_result.success:
            for line in interfaces_result.output.strip().split("\n"):
                if line.strip():
                    interfaces.append(line.strip())

        return DeviceInfo(
            hostname=hostname,
            vendor="linux",
            model=model,
            version=f"{version} (kernel: {kernel_version})",
            serial_number=None,
            interfaces=interfaces,
            zones=["INPUT", "OUTPUT", "FORWARD"],  # Standard iptables chains
        )

    def parse_configuration(self, raw_config: str) -> List[ConfigurationItem]:
        """Parse iptables configuration into structured items."""
        items = []
        lines = raw_config.split("\n")

        current_table = None
        current_chain = None

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Detect table
            if line.startswith("*"):
                current_table = line[1:]
                continue

            # Detect chain definitions
            if line.startswith(":"):
                current_chain = line.split()[0][1:]
                continue

            # Parse rules
            if line.startswith("-A"):
                items.append(
                    ConfigurationItem(
                        type="firewall_rule",
                        content=line,
                        line_number=line_num,
                        section=f"{current_table}:{current_chain}"
                        if current_table and current_chain
                        else None,
                        raw_config=line,
                    )
                )
            elif line.startswith("-t nat"):
                items.append(
                    ConfigurationItem(
                        type="nat_rule",
                        content=line,
                        line_number=line_num,
                        section=current_table,
                        raw_config=line,
                    )
                )

        return items

    async def get_firewall_rules(self) -> List[ConfigurationItem]:
        """Get all iptables rules."""
        result = await self.execute_command("iptables -L -n --line-numbers")
        if not result.success:
            return []

        rules = []
        current_chain = None

        for line in result.output.split("\n"):
            line = line.strip()

            # Detect chain headers
            if line.startswith("Chain"):
                current_chain = line.split()[1]
                continue

            # Skip headers and empty lines
            if not line or line.startswith("num") or line.startswith("target"):
                continue

            # Parse rule lines
            if current_chain and any(char.isdigit() for char in line[:5]):
                rules.append(
                    ConfigurationItem(
                        type="firewall_rule",
                        content=line,
                        section=current_chain,
                        raw_config=line,
                    )
                )

        return rules

    async def get_nat_rules(self) -> List[ConfigurationItem]:
        """Get all NAT rules."""
        result = await self.execute_command("iptables -t nat -L -n --line-numbers")
        if not result.success:
            return []

        rules = []
        current_chain = None

        for line in result.output.split("\n"):
            line = line.strip()

            if line.startswith("Chain"):
                current_chain = line.split()[1]
                continue

            if not line or line.startswith("num") or line.startswith("target"):
                continue

            if current_chain and any(char.isdigit() for char in line[:5]):
                rules.append(
                    ConfigurationItem(
                        type="nat_rule",
                        content=line,
                        section=current_chain,
                        raw_config=line,
                    )
                )

        return rules

    async def get_zones(self) -> List[str]:
        """Get all iptables chains (zones)."""
        result = await self.execute_command(
            "iptables -L | grep '^Chain' | awk '{print $2}'"
        )
        zones = []

        if result.success:
            for line in result.output.split("\n"):
                line = line.strip()
                if line:
                    zones.append(line)

        return zones

    def rule_to_commands(self, rule: BaseRule) -> List[str]:
        if not isinstance(rule, FirewallRule):
            return []
        return firewall_rule_to_commands(rule)

    def validate_commands(self, commands: List[str]) -> List[str]:
        """Validate iptables commands."""
        errors = []

        for command in commands:
            if not command.strip():
                errors.append("Empty command")
                continue

            # Basic iptables validation
            if not command.startswith("iptables"):
                errors.append(f"Command must start with 'iptables': {command}")
                continue

            # Check for required components
            parts = command.split()
            if len(parts) < 3:
                errors.append(f"Invalid iptables syntax: {command}")
                continue

            # Validate chain
            if "-A" in parts:
                chain_idx = parts.index("-A") + 1
                if chain_idx >= len(parts):
                    errors.append(f"Missing chain after -A: {command}")
                elif parts[chain_idx] not in [
                    "INPUT",
                    "OUTPUT",
                    "FORWARD",
                    "PREROUTING",
                    "POSTROUTING",
                ]:
                    errors.append(f"Invalid chain '{parts[chain_idx]}': {command}")

        return errors

    async def apply_commands(
        self, commands: List[str], dry_run: bool = False
    ) -> List[CommandResult]:
        """Apply iptables commands to the device."""
        if dry_run:
            # Simulate command execution
            results = []
            for command in commands:
                results.append(
                    CommandResult(
                        command=command,
                        success=True,
                        output=f"DRY RUN: Would execute: {command}",
                        execution_time=0.0,
                    )
                )
            return results

        if not self._ssh_client:
            return [
                CommandResult(
                    command="",
                    success=False,
                    output="",
                    error="Not connected to device",
                    execution_time=0.0,
                )
            ]

        logger.info("Applying %s iptables commands...", len(commands))

        # Option 1: Execute commands individually (safer, stops on first error)
        results = await self.execute_commands_batch(commands, stop_on_error=True)

        return results

    def get_test_command(self) -> str:
        """Get a simple command to test connectivity."""
        return "iptables --version"
