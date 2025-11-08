"""
Linux iptables firewall device implementation.
"""

import re
from typing import List, Optional

from ..core.credentials import credential_manager
from ..core.logging_config import get_logger
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
            self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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
                        self._ssh_client.set_missing_host_key_policy(
                            paramiko.AutoAddPolicy()
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
                        self._ssh_client.set_missing_host_key_policy(
                            paramiko.AutoAddPolicy()
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

        try:
            import time

            start_time = time.time()
            original_command = command

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

            # Decode output with error handling
            try:
                output = stdout_data.decode("utf-8")
            except UnicodeDecodeError:
                output = stdout_data.decode("utf-8", errors="replace")

            try:
                error = stderr_data.decode("utf-8") if stderr_data else None
            except UnicodeDecodeError:
                error = (
                    stderr_data.decode("utf-8", errors="replace")
                    if stderr_data
                    else None
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
        """Build a shell command with proper escaping."""
        # Start with a clean shell environment
        shell_parts = []

        # Set error handling (fail on any error)
        shell_parts.append("set -e")

        # Handle sudo if needed
        if use_sudo:
            # Use sudo without password (assumes passwordless sudo or existing sudo session)
            shell_parts.append(f"sudo {command}")
        else:
            shell_parts.append(command)

        # Join with && to ensure proper error propagation
        return " && ".join(shell_parts)

    def _escape_shell_string(self, string: str) -> str:
        """Escape a string for safe shell execution"""
        import shlex

        return shlex.quote(string)

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

    async def execute_script(
        self, script_content: str, use_sudo: bool = False
    ) -> CommandResult:
        """Execute a shell script"""
        import base64

        # Encode script content to avoid shell escaping issues
        script_b64 = base64.b64encode(script_content.encode("utf-8")).decode("ascii")

        # Create a command that decodes and executes the script
        decode_and_run = f"echo '{script_b64}' | base64 -d | /bin/bash"

        return await self.execute_command(decode_and_run, use_sudo=use_sudo)

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
        """Convert a rule to iptables commands."""
        logger.debug("Converting rule to commands")
        logger.debug("Rule type: %s", type(rule).__name__)
        logger.debug("Rule name: %s", getattr(rule, "name", "unnamed"))
        logger.debug("Is FirewallRule: %s", isinstance(rule, FirewallRule))

        if hasattr(rule, "__dict__"):
            logger.debug("Rule attributes: %s", rule.__dict__)

        if not isinstance(rule, FirewallRule):
            logger.debug("Rule is not a FirewallRule, returning empty list")
            return []

        logger.debug("Processing FirewallRule")
        logger.debug("Direction: %s", getattr(rule, "direction", "unknown"))
        logger.debug("Action: %s", getattr(rule, "action", "unknown"))
        logger.debug("Protocol: %s", getattr(rule, "protocol", "unknown"))

        # Determine chain based on direction
        chain = "INPUT"
        if hasattr(rule, "direction") and rule.direction.value == "outbound":
            chain = "OUTPUT"
        elif hasattr(rule, "direction") and rule.direction.value == "bidirectional":
            # Create rules for both directions
            logger.debug("Creating bidirectional rules for INPUT and OUTPUT")
            input_rules = self._build_iptables_rule(rule, "INPUT")
            output_rules = self._build_iptables_rule(rule, "OUTPUT")
            combined_rules = input_rules + output_rules
            logger.debug(
                "Generated %s bidirectional commands: %s",
                len(combined_rules),
                combined_rules,
            )
            return combined_rules

        logger.debug("Creating rule for chain: %s", chain)
        generated_commands = self._build_iptables_rule(rule, chain)
        logger.debug(
            "Generated %s commands: %s", len(generated_commands), generated_commands
        )
        return generated_commands

    def _build_iptables_rule(self, rule: FirewallRule, chain: str) -> List[str]:
        """Build iptables rule for a specific chain."""
        logger.debug("Building iptables rule for chain: %s", chain)
        cmd_parts = ["iptables", "-A", chain]

        # Protocol
        if rule.protocol:
            logger.debug("Adding protocol: %s", rule.protocol.name)
            cmd_parts.extend(["-p", rule.protocol.name])

        # Source IPs
        if rule.source_ips:
            source_ip = rule.source_ips[0]  # Use first source IP
            logger.debug("Adding source IP: %s", source_ip)
            from ..core.objects import IPAddress, IPRange

            if isinstance(source_ip, IPAddress):
                cmd_parts.extend(["-s", source_ip.address])
            elif isinstance(source_ip, IPRange):
                cmd_parts.extend(["-s", source_ip.cidr])

        # Destination IPs
        if rule.destination_ips:
            dest_ip = rule.destination_ips[0]  # Use first destination IP
            logger.debug("Adding destination IP: %s", dest_ip)
            from ..core.objects import IPAddress, IPRange

            if isinstance(dest_ip, IPAddress):
                cmd_parts.extend(["-d", dest_ip.address])
            elif isinstance(dest_ip, IPRange):
                cmd_parts.extend(["-d", dest_ip.cidr])

        # Destination ports
        if (
            rule.destination_ports
            and rule.protocol
            and rule.protocol.name in ["tcp", "udp"]
        ):
            port = rule.destination_ports[0]
            logger.debug("Adding destination port: %s", port)
            if port.is_single():
                cmd_parts.extend(["--dport", str(port.number)])
            elif port.is_range():
                cmd_parts.extend(["--dport", f"{port.range_start}:{port.range_end}"])

        # Source ports
        if rule.source_ports and rule.protocol and rule.protocol.name in ["tcp", "udp"]:
            port = rule.source_ports[0]
            logger.debug("Adding source port: %s", port)
            if port.is_single():
                cmd_parts.extend(["--sport", str(port.number)])
            elif port.is_range():
                cmd_parts.extend(["--sport", f"{port.range_start}:{port.range_end}"])

        # Action
        logger.debug("Adding action: %s", rule.action)
        if rule.action == Action.ALLOW:
            cmd_parts.extend(["-j", "ACCEPT"])
        elif rule.action == Action.DENY:
            cmd_parts.extend(["-j", "DROP"])
        elif rule.action == Action.DROP:
            cmd_parts.extend(["-j", "DROP"])
        elif rule.action == Action.REJECT:
            cmd_parts.extend(["-j", "REJECT"])

        # Logging
        if rule.log_traffic:
            logger.debug("Adding logging")
            log_cmd = cmd_parts[:-2] + [
                "-j",
                "LOG",
                "--log-prefix",
                f"[{rule.name or 'RULE'}] ",
            ]
            final_commands = [" ".join(log_cmd), " ".join(cmd_parts)]
            logger.debug("Final commands with logging: %s", final_commands)
            return final_commands

        final_command = [" ".join(cmd_parts)]
        logger.debug("Final command: %s", final_command)
        return final_command

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
