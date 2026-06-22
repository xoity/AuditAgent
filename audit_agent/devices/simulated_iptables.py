"""Deterministic, persistent iptables simulator for CLI tests and demos."""

import datetime
import json
from pathlib import Path
from typing import List, Optional

from .base import CommandResult, DeviceConfiguration, DeviceInfo
from .linux_iptables import LinuxIptables


class SimulatedLinuxIptables(LinuxIptables):
    def __init__(
        self,
        host: str,
        state_file: str,
        seed: int = 0,
        fail_on_command: Optional[str] = None,
    ):
        super().__init__(host=host, username="sandbox")
        self.state_file = Path(state_file)
        self.seed = seed
        self.fail_on_command = fail_on_command

    def _load_rules(self) -> List[str]:
        if not self.state_file.exists():
            self._save_rules([])
        return json.loads(self.state_file.read_text())["rules"]

    def _save_rules(self, rules: List[str]) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_file.with_suffix(self.state_file.suffix + ".tmp")
        temporary.write_text(json.dumps({"seed": self.seed, "rules": rules}, indent=2))
        temporary.replace(self.state_file)

    async def connect(self) -> bool:
        self._connected = True
        self._device_info = await self.get_device_info()
        self._load_rules()
        return True

    async def disconnect(self) -> None:
        self._connected = False

    async def get_device_info(self) -> DeviceInfo:
        return DeviceInfo(
            hostname=self.connection.host,
            vendor="linux-simulator",
            model=f"deterministic-sandbox-{self.seed}",
            version="1",
            interfaces=["lo", "eth0"],
            zones=["INPUT", "OUTPUT", "FORWARD"],
        )

    def _save_output(self) -> str:
        rules = "\n".join(self._load_rules())
        return f"*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n{rules}\nCOMMIT\n"

    async def execute_command(
        self, command: str, use_sudo: Optional[bool] = None
    ) -> CommandResult:
        if self.fail_on_command and self.fail_on_command in command:
            return CommandResult(
                command=command,
                success=False,
                output="",
                error="Deterministic simulated failure",
                exit_code=1,
                execution_time=0.0,
            )
        if command == "iptables-save":
            output = self._save_output()
        elif command == "ip6tables-save":
            output = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
        elif command.startswith("iptables -A "):
            rules = self._load_rules()
            rule = command.removeprefix("iptables ")
            if rule not in rules:
                rules.append(rule)
                self._save_rules(rules)
            output = "Rule applied"
        elif command.startswith("iptables -D "):
            rules = self._load_rules()
            rule = "-A " + command.removeprefix("iptables -D ")
            if rule in rules:
                rules.remove(rule)
                self._save_rules(rules)
            output = "Rule removed"
        elif command in {"iptables --version", "hostname"}:
            output = "iptables v1.8.9" if "version" in command else self.connection.host
        else:
            return CommandResult(
                command=command,
                success=False,
                output="",
                error=f"Unsupported simulated command: {command}",
                exit_code=2,
                execution_time=0.0,
            )
        return CommandResult(
            command=command,
            success=True,
            output=output,
            exit_code=0,
            execution_time=0.0,
        )

    async def get_configuration(self) -> DeviceConfiguration:
        raw_config = "# IPv4 Rules\n" + self._save_output()
        return DeviceConfiguration(
            device_info=self._device_info or await self.get_device_info(),
            raw_config=raw_config,
            parsed_items=self.parse_configuration(raw_config),
            timestamp=datetime.datetime.now().isoformat(),
        )

    async def backup_configuration(self) -> str:
        return json.dumps({"rules": self._load_rules()})

    async def restore_configuration(self, backup: str) -> CommandResult:
        self._save_rules(json.loads(backup)["rules"])
        return CommandResult(
            command="restore_configuration",
            success=True,
            output="Rollback snapshot restored",
            execution_time=0.0,
        )

    async def apply_commands(
        self, commands: List[str], dry_run: bool = False
    ) -> List[CommandResult]:
        if dry_run:
            return [
                CommandResult(
                    command=command,
                    success=True,
                    output=f"DRY RUN: Would validate: {command}",
                    execution_time=0.0,
                )
                for command in commands
            ]
        return await self.execute_commands_batch(commands, stop_on_error=True)
