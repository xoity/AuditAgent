"""
Linux iptables firewall device implementation.
"""

import re
from typing import List, Optional
from .base import (
    FirewallDevice,
    DeviceConnection,
    DeviceInfo,
    ConfigurationItem,
    CommandResult,
    DeviceConfiguration,
)
from ..core.rules import BaseRule, FirewallRule, Action


class LinuxIptables(FirewallDevice):
    """Linux server with iptables firewall implementation."""

    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
        sudo_password: Optional[str] = None,
    ):
        from .base import DeviceCredentials

        credentials = DeviceCredentials(
            username=username, password=password, private_key=private_key
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
                key = paramiko.RSAKey.from_private_key_file(
                    self.connection.credentials.private_key
                )
                connect_kwargs["pkey"] = key
            elif self.connection.credentials.password:
                # Use password authentication
                connect_kwargs["password"] = self.connection.credentials.password
            else:
                raise ValueError("Either password or private_key must be provided")

            self._ssh_client.connect(**connect_kwargs)

            # Test connection with a simple command
            result = await self.execute_command("echo 'test'")
            if result.success:
                self._connected = True
                # Get device info
                self._device_info = await self.get_device_info()
                return True

        except Exception as e:
            self._connected = False
            print(f"Failed to connect to {self.connection.host}: {e}")

        return False

    async def disconnect(self) -> None:
        """Disconnect from the server."""
        if self._ssh_client:
            self._ssh_client.close()
            self._ssh_client = None
        self._connected = False

    async def execute_command(self, command: str) -> CommandResult:
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

            # Add sudo if needed for iptables commands
            if any(
                cmd in command
                for cmd in [
                    "iptables",
                    "ip6tables",
                    "iptables-save",
                    "iptables-restore",
                ]
            ):
                if self.sudo_password:
                    command = f"echo '{self.sudo_password}' | sudo -S {command}"
                else:
                    command = f"sudo {command}"

            stdin, stdout, stderr = self._ssh_client.exec_command(command)

            # Wait for command to complete
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode("utf-8")
            error = stderr.read().decode("utf-8")

            execution_time = time.time() - start_time

            return CommandResult(
                command=command,
                success=exit_code == 0,
                output=output,
                error=error if error else None,
                exit_code=exit_code,
                execution_time=execution_time,
            )

        except Exception as e:
            return CommandResult(
                command=command,
                success=False,
                output="",
                error=str(e),
                execution_time=0.0,
            )

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
        if not isinstance(rule, FirewallRule):
            return []

        # Determine chain based on direction
        chain = "INPUT"
        if rule.direction.value == "outbound":
            chain = "OUTPUT"
        elif rule.direction.value == "bidirectional":
            # Create rules for both directions
            return self._build_iptables_rule(rule, "INPUT") + self._build_iptables_rule(
                rule, "OUTPUT"
            )

        return self._build_iptables_rule(rule, chain)

    def _build_iptables_rule(self, rule: FirewallRule, chain: str) -> List[str]:
        """Build iptables rule for a specific chain."""
        cmd_parts = ["iptables", "-A", chain]

        # Protocol
        if rule.protocol:
            cmd_parts.extend(["-p", rule.protocol.name])

        # Source IPs
        if rule.source_ips:
            source_ip = rule.source_ips[0]  # Use first source IP
            from ..core.objects import IPAddress, IPRange

            if isinstance(source_ip, IPAddress):
                cmd_parts.extend(["-s", source_ip.address])
            elif isinstance(source_ip, IPRange):
                cmd_parts.extend(["-s", source_ip.cidr])

        # Destination IPs
        if rule.destination_ips:
            dest_ip = rule.destination_ips[0]  # Use first destination IP
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
            if port.is_single():
                cmd_parts.extend(["--dport", str(port.number)])
            elif port.is_range():
                cmd_parts.extend(["--dport", f"{port.range_start}:{port.range_end}"])

        # Source ports
        if rule.source_ports and rule.protocol and rule.protocol.name in ["tcp", "udp"]:
            port = rule.source_ports[0]
            if port.is_single():
                cmd_parts.extend(["--sport", str(port.number)])
            elif port.is_range():
                cmd_parts.extend(["--sport", f"{port.range_start}:{port.range_end}"])

        # Action
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
            log_cmd = cmd_parts[:-2] + [
                "-j",
                "LOG",
                "--log-prefix",
                f"[{rule.name or 'RULE'}] ",
            ]
            return [" ".join(log_cmd), " ".join(cmd_parts)]

        return [" ".join(cmd_parts)]

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
        """Apply iptables commands."""
        results = []

        if dry_run:
            # Simulate command execution
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

        # Execute each command
        for command in commands:
            result = await self.execute_command(command)
            results.append(result)

            # Stop on first failure
            if not result.success:
                break

        return results

    def get_test_command(self) -> str:
        """Get a simple command to test connectivity."""
        return "iptables --version"
