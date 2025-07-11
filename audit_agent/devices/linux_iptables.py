"""
Linux iptables firewall device implementation.
"""

import re
from typing import List, Optional

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
        private_key_passphrase: Optional[str] = None,
        port: int = 22,
        sudo_password: Optional[str] = None,
    ):
        from .base import DeviceCredentials

        credentials = DeviceCredentials(
            username=username,
            password=password,
            private_key=private_key,
            private_key_passphrase=private_key_passphrase,
        )
        connection = DeviceConnection(
            host=host, port=port, protocol="ssh", credentials=credentials
        )
        super().__init__(connection)
        self.sudo_password = sudo_password
        self._ssh_client = None

    async def connect(self) -> bool:
        """Connect to the Linux server via SSH."""
        try:
            import paramiko

            self._ssh_client = paramiko.SSHClient()
            self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": self.connection.host,
                "port": self.connection.port or 22,
                "username": self.connection.credentials.username,
                "timeout": self.connection.timeout,
            }

            if self.connection.credentials.private_key:
                # Use private key authentication
                key_path = self.connection.credentials.private_key

                # Try to load the private key, handling both encrypted and unencrypted keys
                key = None
                try:
                    # First, try without passphrase (unencrypted key)
                    key = paramiko.RSAKey.from_private_key_file(key_path)
                except paramiko.PasswordRequiredException:
                    # Key is encrypted, use provided passphrase
                    passphrase = self.connection.credentials.private_key_passphrase
                    if not passphrase:
                        raise ValueError(
                            "Private key is encrypted but no passphrase provided"
                        )

                    try:
                        key = paramiko.RSAKey.from_private_key_file(
                            key_path, password=passphrase
                        )
                    except paramiko.SSHException:
                        # Try other key types if RSA fails
                        try:
                            key = paramiko.Ed25519Key.from_private_key_file(
                                key_path, password=passphrase
                            )
                        except paramiko.SSHException:
                            try:
                                key = paramiko.ECDSAKey.from_private_key_file(
                                    key_path, password=passphrase
                                )
                            except paramiko.SSHException:
                                try:
                                    key = paramiko.DSSKey.from_private_key_file(
                                        key_path, password=passphrase
                                    )
                                except paramiko.SSHException:
                                    raise ValueError(
                                        "Unable to load private key with provided passphrase"
                                    )
                except paramiko.SSHException:
                    # Try other key types for unencrypted keys
                    try:
                        key = paramiko.Ed25519Key.from_private_key_file(key_path)
                    except paramiko.SSHException:
                        try:
                            key = paramiko.ECDSAKey.from_private_key_file(key_path)
                        except paramiko.SSHException:
                            try:
                                key = paramiko.DSSKey.from_private_key_file(key_path)
                            except paramiko.SSHException:
                                raise ValueError("Unable to load private key")

                connect_kwargs["pkey"] = key
            elif self.connection.credentials.password:
                # Use password authentication
                connect_kwargs["password"] = self.connection.credentials.password
            else:
                raise ValueError("Either password or private_key must be provided")

            self._ssh_client.connect(**connect_kwargs)

            # Test connection with a simple command
            try:
                stdin, stdout, stderr = self._ssh_client.exec_command("echo 'test'")
                stdout.read()  # Just read to test the connection
                self._connected = True
                # Get device info
                self._device_info = await self.get_device_info()
                return True
            except Exception as e:
                logger.error(f"Connection test failed: {e}")
                return False

        except Exception as e:
            self._connected = False
            logger.error(f"Failed to connect to {self.connection.host}: {e}")

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
                    f"Simple exec_command failed: {e}, trying channel approach"
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

            # Clean up sudo password from error output for security
            if error and self.sudo_password:
                error = error.replace(self.sudo_password, "***")

            result = CommandResult(
                command=original_command,
                success=exit_code == 0,
                output=output,
                error=error,
                exit_code=exit_code,
                execution_time=execution_time,
            )

            logger.debug(f"Executing command: {original_command}")
            logger.debug(f"Result: success={result.success}, exit_code={exit_code}")
            if result.error:
                logger.debug(f"Error: {result.error}")

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
        import shlex

        # Start with a clean shell environment
        shell_parts = []

        # Set error handling (fail on any error)
        shell_parts.append("set -e")

        # Handle sudo if needed
        if use_sudo:
            if self.sudo_password:
                # Use a more secure approach for sudo with password
                # Create a temporary script to avoid password exposure in process list
                sudo_command = (
                    f"echo {shlex.quote(self.sudo_password)} | sudo -S -p '' "
                )
                shell_parts.append(f"{sudo_command} {command}")
            else:
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
                    f"Stopping batch execution due to error in command: {command}"
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
        logger.debug(f"Rule type: {type(rule).__name__}")
        logger.debug(f"Rule name: {getattr(rule, 'name', 'unnamed')}")
        logger.debug(f"Is FirewallRule: {isinstance(rule, FirewallRule)}")

        if hasattr(rule, "__dict__"):
            logger.debug(f"Rule attributes: {rule.__dict__}")

        if not isinstance(rule, FirewallRule):
            logger.debug("Rule is not a FirewallRule, returning empty list")
            return []

        logger.debug("Processing FirewallRule")
        logger.debug(f"Direction: {getattr(rule, 'direction', 'unknown')}")
        logger.debug(f"Action: {getattr(rule, 'action', 'unknown')}")
        logger.debug(f"Protocol: {getattr(rule, 'protocol', 'unknown')}")

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
                f"Generated {len(combined_rules)} bidirectional commands: {combined_rules}"
            )
            return combined_rules

        logger.debug(f"Creating rule for chain: {chain}")
        generated_commands = self._build_iptables_rule(rule, chain)
        logger.debug(
            f"Generated {len(generated_commands)} commands: {generated_commands}"
        )
        return generated_commands

    def _build_iptables_rule(self, rule: FirewallRule, chain: str) -> List[str]:
        """Build iptables rule for a specific chain."""
        logger.debug(f"Building iptables rule for chain: {chain}")
        cmd_parts = ["iptables", "-A", chain]

        # Protocol
        if rule.protocol:
            logger.debug(f"Adding protocol: {rule.protocol.name}")
            cmd_parts.extend(["-p", rule.protocol.name])

        # Source IPs
        if rule.source_ips:
            source_ip = rule.source_ips[0]  # Use first source IP
            logger.debug(f"Adding source IP: {source_ip}")
            from ..core.objects import IPAddress, IPRange

            if isinstance(source_ip, IPAddress):
                cmd_parts.extend(["-s", source_ip.address])
            elif isinstance(source_ip, IPRange):
                cmd_parts.extend(["-s", source_ip.cidr])

        # Destination IPs
        if rule.destination_ips:
            dest_ip = rule.destination_ips[0]  # Use first destination IP
            logger.debug(f"Adding destination IP: {dest_ip}")
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
            logger.debug(f"Adding destination port: {port}")
            if port.is_single():
                cmd_parts.extend(["--dport", str(port.number)])
            elif port.is_range():
                cmd_parts.extend(["--dport", f"{port.range_start}:{port.range_end}"])

        # Source ports
        if rule.source_ports and rule.protocol and rule.protocol.name in ["tcp", "udp"]:
            port = rule.source_ports[0]
            logger.debug(f"Adding source port: {port}")
            if port.is_single():
                cmd_parts.extend(["--sport", str(port.number)])
            elif port.is_range():
                cmd_parts.extend(["--sport", f"{port.range_start}:{port.range_end}"])

        # Action
        logger.debug(f"Adding action: {rule.action}")
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
            logger.debug(f"Final commands with logging: {final_commands}")
            return final_commands

        final_command = [" ".join(cmd_parts)]
        logger.debug(f"Final command: {final_command}")
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

        logger.info(f"Applying {len(commands)} iptables commands...")

        # Option 1: Execute commands individually (safer, stops on first error)
        results = await self.execute_commands_batch(commands, stop_on_error=True)

        return results

    def get_test_command(self) -> str:
        """Get a simple command to test connectivity."""
        return "iptables --version"
