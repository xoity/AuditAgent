import pytest

from audit_agent.devices.linux_iptables import firewall_rule_to_commands
from benchmarks.run_fault_injection import run as run_fault_injection
from benchmarks.run_llm_comparison import (
    _NoRedirect,
    build_scenarios,
    run as run_llm_comparison,
)
from benchmarks.run_scalability import _time_audit_with_peak, run as run_scalability
from benchmarks.synthetic import generate_device_lines, generate_policy


def test_synthetic_policy_and_device_rules_are_unique_and_equal():
    lines = generate_device_lines(1000, seed=7)
    policy = generate_policy(1000, seed=7)
    policy_lines = [
        command.removeprefix("iptables ")
        for rule in policy.firewall_rules
        for command in firewall_rule_to_commands(rule)
    ]

    assert len(set(lines)) == len(lines)
    assert policy_lines == lines


def test_llm_scenario_and_provider_failures_are_recorded():
    scenarios = build_scenarios(2)
    assert scenarios[1].drift == "shadowed_rule"
    assert scenarios[1].device_rules[0] == "-A INPUT -j DROP"
    calls = 0

    def call(prompt, model):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("provider failed")
        return "iptables -A INPUT -j ACCEPT"

    result = run_llm_comparison(scenarios, "test", "test", call)

    assert result["provider_errors"] == 1
    assert result["accepted"] == 1
    assert len(result["results"]) == 2


def test_provider_redirects_are_rejected():
    assert (
        _NoRedirect().redirect_request(
            object(), None, 302, "Found", {}, "https://attacker.example"
        )
        is None
    )


def test_scalability_rejects_non_positive_repeat():
    with pytest.raises(ValueError, match="repeat must be positive"):
        run_scalability([1], 0, 0)


def test_scalability_samples_peak_memory_during_audit():
    elapsed, peak_delta = _time_audit_with_peak(10, 0)

    assert elapsed >= 0
    assert peak_delta >= 0


@pytest.mark.asyncio
async def test_fault_scenarios_restore_clean_baselines(tmp_path):
    outcomes = await run_fault_injection(str(tmp_path))

    assert len(outcomes) == 3
    assert all(outcome.recovered for outcome in outcomes)
