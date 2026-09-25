"""
End-to-end live AI check: audit -> OpenCode remedy -> re-audit.

Requires a configured OpenCode install (model opencode-go/deepseek-v4.1-flash).
Not part of the unit suite; run manually:
    .venv/bin/python benchmarks/live_ai_remediation.py
"""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit_agent.ai.config import AIConfig, AIProvider
from audit_agent.ai.remediation import AIRemediationEngine
from audit_agent.audit.engine import AuditEngine
from audit_agent.core.policy import NetworkPolicy
from audit_agent.core.rules import FirewallRule
from audit_agent.devices.simulated_iptables import SimulatedLinuxIptables


def build_policy() -> NetworkPolicy:
    policy = NetworkPolicy("live-ai-policy")
    ssh = FirewallRule(name="allow-ssh", description="Allow SSH")
    ssh.allow_inbound().tcp().port(22)
    policy.add_firewall_rule(ssh)

    http = FirewallRule(name="allow-http", description="Allow HTTP")
    http.allow_inbound().tcp().port(80)
    policy.add_firewall_rule(http)
    return policy


def build_drifted_device(state_file: str) -> SimulatedLinuxIptables:
    device = SimulatedLinuxIptables(host="live-ai-sim", state_file=state_file)
    # Device has HTTP on the WRONG port (8080) and no SSH at all -> drift.
    device._save_rules(
        [
            "-A INPUT -p tcp --dport 8080 -j ACCEPT",
        ]
    )
    return device


def main() -> int:
    tmpdir = tempfile.mkdtemp(prefix="aa-live-ai-")
    device = build_drifted_device(str(Path(tmpdir) / "state.json"))
    policy = build_policy()
    devices = [device]

    audit_engine = AuditEngine()
    before = asyncio.run(audit_engine.audit_policy(policy, devices))
    print(f"[1] initial compliance: {before.overall_compliance_percentage:.1f}%")
    print(f"    issues: {before.total_issues}")

    config = AIConfig.load_from_env()
    print(f"    provider: {config.default_provider.value}")
    print(f"    model: {config.providers['opencode'].model}")

    engine = AIRemediationEngine(config)
    yaml_text, after = engine.generate_and_validate(
        audit_result=before,
        original_policy=policy,
        devices=devices,
        provider=AIProvider.OPENCODE,
        max_iterations=2,
    )

    print(f"[2] AI returned {len(yaml_text)} chars of YAML")
    parsed = NetworkPolicy.from_yaml(yaml_text)
    print(f"    parses as NetworkPolicy, rules: {len(parsed.firewall_rules)}")
    print(f"[3] post-remediation compliance: {after.overall_compliance_percentage:.1f}%")
    print(f"    issues: {after.total_issues}")

    ok = after.overall_compliance_percentage >= before.overall_compliance_percentage
    print("RESULT:", "AI flow produced a valid, re-auditable policy" if ok else "NO IMPROVEMENT")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
