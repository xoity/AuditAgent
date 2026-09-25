"""Tests for semantic anomaly detection (shadowing, redundancy, subsumption)."""

import pytest

from audit_agent.audit.anomaly import analyze_rules, covers, parse_rule
from audit_agent.audit.engine import AuditEngine, RuleComparer
from audit_agent.devices.base import ConfigurationItem


def _items(*contents):
    return [
        ConfigurationItem(
            type="firewall_rule",
            content=content,
            line_number=index + 1,
            section="filter:INPUT",
            raw_config="\n".join(contents),
        )
        for index, content in enumerate(contents)
    ]


def _rules(*contents):
    parsed = [parse_rule(content, i) for i, content in enumerate(contents)]
    return [p for p in parsed if p is not None]


class TestParsing:
    def test_parses_core_fields(self):
        rule = parse_rule("-A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j DROP", 0)
        assert rule.chain == "INPUT"
        assert rule.action == "DROP"
        assert rule.protocol == "tcp"
        assert str(rule.src) == "10.0.0.0/8"
        assert rule.dports == [(22, 22)]
        assert rule.terminal

    def test_ignores_non_rule_lines(self):
        assert parse_rule("COMMIT", 0) is None
        assert parse_rule(":INPUT ACCEPT [0:0]", 1) is None

    def test_negation_marked_unmodelled(self):
        rule = parse_rule("-A INPUT ! -s 10.0.0.0/8 -j ACCEPT", 0)
        assert rule.unmodelled

    def test_log_is_not_terminal(self):
        rule = parse_rule("-A INPUT -j LOG --log-prefix 'x'", 0)
        assert not rule.terminal

    def test_ipv6_source_is_unmodelled(self):
        rule = parse_rule("-A INPUT -s 2001:db8::/32 -j ACCEPT", 0)
        assert rule.unmodelled

    def test_protocol_match_is_modelled_only_for_same_protocol(self):
        tcp = parse_rule("-A INPUT -m tcp -p tcp --dport 22 -j ACCEPT", 0)
        mismatch = parse_rule("-A INPUT -m udp -p tcp --dport 22 -j ACCEPT", 1)
        assert not tcp.unmodelled
        assert mismatch.unmodelled

    def test_reject_with_is_target_only(self):
        rule = parse_rule("-A INPUT -p tcp -j REJECT --reject-with tcp-reset", 0)
        assert not rule.unmodelled


class TestCovers:
    def test_bare_rule_covers_specific(self):
        broad, narrow = _rules(
            "-A INPUT -j ACCEPT",
            "-A INPUT -s 10.0.0.1 -p tcp --dport 22 -j DROP",
        )
        assert covers(broad, narrow)

    def test_cidr_subsumption(self):
        parent, child = _rules(
            "-A INPUT -s 192.168.1.0/24 -j DROP",
            "-A INPUT -s 192.168.1.0/25 -j DROP",
        )
        assert covers(parent, child)
        assert not covers(child, parent)

    def test_port_interval_containment(self):
        outer, inner = _rules(
            "-A INPUT -p tcp --dport 1024:65535 -j ACCEPT",
            "-A INPUT -p tcp --dport 8080 -j ACCEPT",
        )
        assert covers(outer, inner)

    def test_any_port_does_not_fit_restricted_port(self):
        outer, inner = _rules(
            "-A INPUT -p tcp --dport 22 -j ACCEPT",
            "-A INPUT -p tcp -j ACCEPT",
        )
        assert not covers(outer, inner)

    def test_protocol_mismatch_is_not_covered(self):
        outer, inner = _rules(
            "-A INPUT -p udp -j DROP",
            "-A INPUT -p tcp -j DROP",
        )
        assert not covers(outer, inner)

    def test_different_chain_is_not_covered(self):
        outer, inner = _rules(
            "-A INPUT -j ACCEPT",
            "-A OUTPUT -j ACCEPT",
        )
        assert not covers(outer, inner)

    def test_unmodelled_rule_never_shadows(self):
        outer, inner = _rules(
            "-A INPUT -m state --state ESTABLISHED -j ACCEPT",
            "-A INPUT -p tcp --dport 22 -j DROP",
        )
        assert not covers(outer, inner)


class TestAnalyzeRules:
    def test_accept_shadowing_drop_rule_is_critical(self):
        cases = _rules(
            "-A INPUT -p tcp --dport 22 -j ACCEPT",
            "-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j DROP",
        )
        anomalies = analyze_rules(cases)
        shadowing = [a for a in anomalies if a.kind == "shadowing"]
        assert len(shadowing) == 1
        assert shadowing[0].severity == "critical"
        assert shadowing[0].rule_index == 1

    def test_identical_action_is_redundancy_not_shadowing(self):
        cases = _rules(
            "-A INPUT -s 192.168.1.0/24 -p tcp --dport 443 -j ACCEPT",
            "-A INPUT -s 192.168.1.0/25 -p tcp --dport 443 -j ACCEPT",
        )
        anomalies = analyze_rules(cases)
        assert [a.kind for a in anomalies] == ["redundancy"]
        assert anomalies[0].severity == "low"

    def test_no_false_positive_when_order_is_safe(self):
        cases = _rules(
            "-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j DROP",
            "-A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT",
        )
        assert analyze_rules(cases) == []

    def test_ipv6_rule_does_not_shadow_ipv4(self):
        cases = _rules(
            "-A INPUT -s 2001:db8::/32 -j ACCEPT",
            "-A INPUT -s 10.0.0.0/8 -j DROP",
        )
        assert analyze_rules(cases) == []

    def test_iptables_save_tcp_and_reject_rules_shadow(self):
        cases = _rules(
            "-A INPUT -p tcp -m tcp --dport 22 -j REJECT --reject-with tcp-reset",
            "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT",
        )
        assert [anomaly.kind for anomaly in analyze_rules(cases)] == ["shadowing"]

    def test_first_covering_rule_is_reported(self):
        cases = _rules(
            "-A INPUT -j ACCEPT",
            "-A INPUT -s 10.0.0.0/8 -j ACCEPT",
            "-A INPUT -s 10.1.0.0/16 -p tcp --dport 22 -j DROP",
        )
        anomalies = analyze_rules(cases)
        for a in anomalies:
            if a.rule_index == 2 and a.kind == "shadowing":
                assert a.related_index == 0
                break
        else:  # pragma: no cover - guarded by assertion above
            pytest.fail("expected shadowing of the DROP rule")


class TestEngineIntegration:
    @pytest.mark.asyncio
    async def test_shadowed_policy_rule_is_not_compliant(self):
        from audit_agent.core.policy import NetworkPolicy
        from audit_agent.core.rules import FirewallRule
        from tests.test_audit_engine import MockDevice

        policy = NetworkPolicy(name="semantic")
        policy.add_firewall_rule(
            FirewallRule(id="r1", name="deny-ssh")
            .deny_inbound()
            .tcp()
            .from_ip("10.0.0.0/8")
            .port(22)
        )

        device = MockDevice(
            _items(
                "-A INPUT -p tcp --dport 22 -j ACCEPT",
                "-A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j DROP",
            )
        )

        result = await AuditEngine().audit_device(policy, device)

        assert result.non_compliant_rules == 1
        kinds = {issue.issue_type for issue in result.issues}
        assert "shadowed_rule" in kinds
        assert "policy_violation" in kinds
        assert any(issue.severity == "critical" for issue in result.issues)


class TestRuleComparerState:
    def test_shadowed_contents_reset_between_devices(self):
        comparer = RuleComparer()
        comparer.set_shadowed_contents(["-A INPUT -j ACCEPT"])
        assert comparer._shadowed_contents
        comparer.set_shadowed_contents([])
        assert comparer._shadowed_contents == set()
