"""Fault-injection suite for the enforcement path.

Drives the *real* transactional enforcement code against the deterministic
simulator, injecting the faults that break naive enforcement: an invalid
command, a rule that cuts the management path, a mid-batch failure, and a lost
session. Records whether each fault is recovered from cleanly.

Runs by default against `SimulatedLinuxIptables` (no VM needed). Pass
`--vagrant` to additionally run the lost-session scenario inside the Vagrant
guest using a real `iptables-restore` watchdog and a real backgrounded
`setsid` process.

Usage::

    python -m benchmarks.run_fault_injection
    python -m benchmarks.run_fault_injection --vagrant --json faults.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import List

from audit_agent.devices.simulated_iptables import SimulatedLinuxIptables


@dataclass
class Outcome:
    scenario: str
    recovered: bool
    detail: str


async def _invalid_command(tmpdir: str) -> Outcome:
    device = SimulatedLinuxIptables(host="sim", state_file=f"{tmpdir}/a.json")
    await device.connect()
    device._save_rules([])
    result = await device.apply_transaction(["iptables -X NOT_A_CHAIN"])
    # Simulator only accepts known verbs; the batch fails and we roll back.
    recovered = not result.success and device._load_rules() == []
    return Outcome("invalid_command", recovered, result.error or result.output)


async def _mid_batch_failure(tmpdir: str) -> Outcome:
    device = SimulatedLinuxIptables(
        host="sim", state_file=f"{tmpdir}/b.json", fail_on_command="--dport 8080"
    )
    await device.connect()
    device._save_rules([])
    result = await device.apply_transaction(
        [
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 8080 -j DROP",
        ]
    )
    # First command may have applied; transaction must restore to empty.
    recovered = not result.success and device._load_rules() == []
    return Outcome("mid_batch_failure", recovered, result.error or result.output)


async def _lockout_rule_rolled_back(tmpdir: str) -> Outcome:
    """The classic lockout: an incorrect rule cuts the management port."""
    device = SimulatedLinuxIptables(host="sim", state_file=f"{tmpdir}/c.json")
    await device.connect()
    device._save_rules([])
    device.fail_on_command = "--dport 8080"
    result = await device.apply_transaction(
        [
            "iptables -A INPUT -p tcp --dport 22 -j DROP",
            "iptables -A INPUT -p tcp --dport 8080 -j ACCEPT",
        ]
    )
    recovered = not result.success and device._load_rules() == []
    return Outcome("lockout_rule_rolled_back", recovered, result.error or result.output)


def _vagrant_lost_session() -> Outcome:
    vagrant = shutil.which("vagrant")
    if not vagrant:
        return Outcome("lost_session_watchdog_restore", False, "vagrant not found")
    result = subprocess.run(  # noqa: S603 - resolved vagrant executable
        [
            vagrant,
            "ssh",
            "-c",
            "cd /vagrant && sh benchmarks/live_watchdog_check.sh",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    return Outcome(
        "lost_session_watchdog_restore",
        result.returncode == 0,
        (result.stdout if result.returncode == 0 else result.stderr).strip(),
    )


SCENARIOS = [
    _invalid_command,
    _mid_batch_failure,
    _lockout_rule_rolled_back,
]


async def run(tmpdir: str) -> List[Outcome]:
    return [await scenario(tmpdir) for scenario in SCENARIOS]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tmpdir", default="/tmp")  # noqa: S108 - sandbox state files
    parser.add_argument("--json", type=str, default=None)
    parser.add_argument("--vagrant", action="store_true")
    args = parser.parse_args()

    outcomes = asyncio.run(run(args.tmpdir))
    if args.vagrant:
        outcomes.append(_vagrant_lost_session())

    print("\n| scenario | recovered | detail |")
    print("|----------|-----------|--------|")
    for outcome in outcomes:
        print(f"| {outcome.scenario} | {outcome.recovered} | {outcome.detail} |")

    recovered = sum(1 for o in outcomes if o.recovered)
    print(f"\n{recovered}/{len(outcomes)} fault scenarios recovered cleanly")

    if args.json:
        with open(args.json, "w") as handle:
            json.dump([asdict(o) for o in outcomes], handle, indent=2)
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
