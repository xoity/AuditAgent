import asyncio
import json
from pathlib import Path

from audit_agent.cli import load_devices, load_policy
from audit_agent.enforcement.engine import EnforcementEngine


def run(coro):
    return asyncio.run(coro)


def test_sandbox_audit_enforce_idempotency_and_rollback(tmp_path):
    policy = load_policy(Path("examples/simple-linux-policy.yaml"))
    state_file = tmp_path / "sandbox.json"
    devices_file = tmp_path / "devices.yaml"
    devices_file.write_text(
        "devices:\n"
        "  - type: simulated_iptables\n"
        "    host: sandbox-42.local\n"
        "    seed: 42\n"
        f"    state_file: {state_file}\n"
    )

    engine = EnforcementEngine()
    device = load_devices(devices_file)[0]
    first = run(engine.enforce_policy(policy, [device], dry_run=False))
    assert first.total_actions_planned == 7
    assert first.total_actions_successful == 7

    device = load_devices(devices_file)[0]
    second = run(engine.enforce_policy(policy, [device], dry_run=False))
    assert second.total_actions_planned == 0
    assert second.total_actions_executed == 0

    before = json.loads(state_file.read_text())
    state_file.unlink()
    devices_file.write_text(
        "devices:\n"
        "  - type: simulated_iptables\n"
        "    host: sandbox-42.local\n"
        "    seed: 42\n"
        f"    state_file: {state_file}\n"
        "    fail_on_command: --dport 80\n"
    )
    device = load_devices(devices_file)[0]
    failed = run(engine.enforce_policy(policy, [device], dry_run=False))
    assert failed.total_actions_failed == 1
    assert failed.device_results[0].rollback_performed
    assert json.loads(state_file.read_text())["rules"] == []
    assert before["rules"]
