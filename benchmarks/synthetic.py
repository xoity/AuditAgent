"""Synthetic firewall rule-set generator + benchmark helpers.

Shared by the benchmarking scripts in this directory. Kept dependency-free
(stdlib only) so the harness runs anywhere the package does.
"""

from __future__ import annotations

import random
from typing import List, Tuple

from audit_agent.core.objects import Protocol
from audit_agent.core.policy import NetworkPolicy
from audit_agent.core.rules import FirewallRule

PROTOCOLS = ["tcp", "udp"]
# Ports worth generating rules for, mirroring a realistic service mix.
COMMON_PORTS = [
    22,
    25,
    53,
    80,
    110,
    143,
    443,
    465,
    587,
    993,
    995,
    3306,
    5432,
    6379,
    8080,
    8443,
    9200,
    27017,
]


def _random_network(rng: random.Random, prefix: int = 24) -> str:
    base = rng.choice([10, 172, 192, 203])
    if base == 10:
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.0/{prefix}"
    if base == 172:
        return f"172.{rng.randint(16, 31)}.{rng.randint(0, 255)}.0/{prefix}"
    if base == 192:
        return f"192.168.{rng.randint(0, 255)}.0/{prefix}"
    return f"203.0.{rng.randint(0, 255)}.0/{prefix}"


def _rule_specs(size: int, seed: int) -> List[Tuple[str, str, int]]:
    rng = random.Random(seed)
    specs = []
    seen = set()
    while len(specs) < size:
        spec = (
            rng.choice(PROTOCOLS),
            _random_network(rng),
            COMMON_PORTS[len(specs) % len(COMMON_PORTS)],
        )
        if spec not in seen:
            seen.add(spec)
            specs.append(spec)
    return specs


def generate_policy(size: int, seed: int = 0) -> NetworkPolicy:
    """Generate a policy with `size` distinct inbound firewall rules."""
    policy = NetworkPolicy(name=f"synthetic-{size}")
    for i, (protocol, source, port) in enumerate(_rule_specs(size, seed)):
        rule = FirewallRule(id=f"r{i}", name=f"rule-{i}")
        (rule.allow_inbound() if i % 2 == 0 else rule.deny_inbound())
        rule.protocol = Protocol(name=protocol)
        rule.from_ip(source)
        rule.port(port)
        policy.add_firewall_rule(rule)
    return policy


def generate_device_lines(size: int, seed: int = 0) -> List[str]:
    """Generate `size` iptables `-A INPUT` lines matching `generate_policy`."""
    lines = []
    for i, (proto, src, port) in enumerate(_rule_specs(size, seed)):
        action = "ACCEPT" if i % 2 == 0 else "DROP"
        lines.append(f"-A INPUT -p {proto} -s {src} --dport {port} -j {action}")
    return lines
