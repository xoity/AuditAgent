"""
Semantic anomaly detection for firewall rule sets.

The classic Al-Shaer & Hamed (2004) firewall anomalies are *ordering* and
*subsumption* problems, not textual ones: a rule can be present in the chain
yet be completely unreachable because an earlier rule already matched every
packet it would have matched.

This module turns each iptables rule into a small, comparable predicate
(network, port set, protocol, interface) and evaluates those predicates in
chain order using only the standard library. It detects:

* shadowing  - an earlier terminal rule fully covers a later rule with a
               *different* action, so the later rule never fires.
* redundancy - an earlier rule fully covers a later rule with the *same*
               action, so the later rule is dead weight.
* subsumption - CIDR/port containment, computed with ``ipaddress`` so that
               192.168.1.0/24 correctly contains 192.168.1.0/25 and
               0.0.0.0/0 contains everything.

Only IPv4 filter-table rules are modelled. Anything we do not understand
(match extensions, negation, ip6tables) makes a rule ineligible as a
*shadower* so we never emit a false positive; it can still be *shadowed*.
"""

from __future__ import annotations

import ipaddress
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# Actions that terminate evaluation of a chain. LOG returns to the chain in
# iptables, so it can never shadow a following rule.
TERMINAL_ACTIONS = {"ACCEPT", "DROP", "REJECT"}
# DROP-like actions deny traffic; ACCEPT allows it.
DENY_ACTIONS = {"DROP", "REJECT"}

# Flags that carry a value we already model; used to skip their argument.
_VALUE_FLAGS = {"-s", "--source", "-d", "--destination", "-p", "--protocol",
                "-j", "--jump", "-i", "--in-interface", "-o", "--out-interface",
                "--dport", "--destination-port", "-m", "--match"}

PortInterval = Tuple[int, int]  # inclusive


@dataclass
class ParsedRule:
    """A normalised, comparable view of one iptables rule."""

    index: int
    chain: str
    action: str
    raw: str
    line_number: Optional[int] = None
    protocol: Optional[str] = None  # None == any
    src: ipaddress.IPv4Network = field(
        default_factory=lambda: ipaddress.IPv4Network("0.0.0.0/0")
    )
    dst: ipaddress.IPv4Network = field(
        default_factory=lambda: ipaddress.IPv4Network("0.0.0.0/0")
    )
    dports: Optional[List[PortInterval]] = None  # None == any
    in_iface: Optional[str] = None
    out_iface: Optional[str] = None
    # Rule carries syntax we do not model (negation, -m extensions, ipv6,
    # multiport, ...). It can still be shadowed, but must not be used as a
    # shadower.
    unmodelled: bool = False

    @property
    def terminal(self) -> bool:
        return self.action in TERMINAL_ACTIONS


def _parse_port_spec(value: str) -> Optional[List[PortInterval]]:
    """Parse ``22``, ``1024:65535`` or ``22,80,443`` into intervals."""
    intervals: List[PortInterval] = []
    for part in value.split(","):
        if ":" in part:
            lo, hi = part.split(":", 1)
            intervals.append((int(lo), int(hi)))
        elif "-" in part:
            lo, hi = part.split("-", 1)
            intervals.append((int(lo), int(hi)))
        else:
            n = int(part)
            intervals.append((n, n))
    return sorted(intervals) if intervals else None


def _parse_network(value: str) -> ipaddress.IPv4Network:
    # iptables accepts a bare IP (implies /32) or CIDR.
    try:
        return ipaddress.IPv4Network(value, strict=False)
    except (ipaddress.AddressValueError, ValueError):
        return ipaddress.IPv4Network("0.0.0.0/0")


def parse_rule(
    content: str, index: int, line_number: Optional[int] = None
) -> Optional[ParsedRule]:
    """Parse an ``-A CHAIN ...`` line. Returns None if it is not one."""
    content = content.strip()
    if not content.startswith("-A "):
        return None

    unmodelled = False
    if "!" in content:
        # Negated matches invert containment; refuse to reason about them.
        unmodelled = True

    try:
        tokens = shlex.split(content)
    except ValueError:
        return None

    chain = tokens[1]
    action = ""
    protocol: Optional[str] = None
    src = ipaddress.IPv4Network("0.0.0.0/0")
    dst = ipaddress.IPv4Network("0.0.0.0/0")
    dports: Optional[List[PortInterval]] = None
    in_iface: Optional[str] = None
    out_iface: Optional[str] = None

    i = 2
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-A", "--append"):
            break
        if tok in ("-p", "--protocol"):
            protocol = tokens[i + 1].lower()
            i += 2
            continue
        if tok in ("-s", "--source"):
            src = _parse_network(tokens[i + 1])
            i += 2
            continue
        if tok in ("-d", "--destination"):
            dst = _parse_network(tokens[i + 1])
            i += 2
            continue
        if tok in ("-j", "--jump"):
            action = tokens[i + 1].upper()
            i += 2
            continue
        if tok in ("-i", "--in-interface"):
            in_iface = tokens[i + 1]
            i += 2
            continue
        if tok in ("-o", "--out-interface"):
            out_iface = tokens[i + 1]
            i += 2
            continue
        if tok in ("--dport", "--destination-port"):
            try:
                dports = _parse_port_spec(tokens[i + 1])
            except ValueError:
                return None
            i += 2
            continue
        if tok in ("--sport", "--source-port"):
            # Source ports are uncommon in these policies; model as unmodelled
            # rather than silently pretending they are absent.
            unmodelled = True
            i += 2
            continue
        if tok in ("-m", "--match"):
            # Match extension (state, comment, conntrack, ...). It narrows the
            # rule, so mark unmodelled.
            unmodelled = True
            i += 2
            continue
        if tok.startswith("-"):
            unmodelled = True
            # Unknown flag may take a value; if the next token is not a flag,
            # skip it so we do not treat it as a positional.
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                i += 2
            else:
                i += 1
            continue
        i += 1

    if not action:
        return None
    # ip6tables has a different address family; only reason about IPv4 here.
    if src.version != 4 or dst.version != 4:
        unmodelled = True

    return ParsedRule(
        index=index,
        chain=chain,
        action=action,
        raw=content,
        line_number=line_number,
        protocol=protocol,
        src=src,
        dst=dst,
        dports=dports,
        in_iface=in_iface,
        out_iface=out_iface,
        unmodelled=unmodelled,
    )


def _covers_ports(
    outer: Optional[List[PortInterval]], inner: Optional[List[PortInterval]]
) -> bool:
    if outer is None:
        return True  # any port covers any narrower set
    if inner is None:
        return False  # outer restricts, inner does not
    for lo, hi in inner:
        if not any(o_lo <= lo and hi <= o_hi for o_lo, o_hi in outer):
            return False
    return True


def covers(a: ParsedRule, b: ParsedRule) -> bool:
    """True if every packet matching *b* also matches *a* (a is a superset)."""
    if a.unmodelled or not a.terminal:
        return False
    if a.chain != b.chain:
        return False
    if a.protocol is not None and a.protocol != b.protocol:
        return False
    if not b.src.subnet_of(a.src):
        return False
    if not b.dst.subnet_of(a.dst):
        return False
    if not _covers_ports(a.dports, b.dports):
        return False
    if a.in_iface is not None and a.in_iface != b.in_iface:
        return False
    if a.out_iface is not None and a.out_iface != b.out_iface:
        return False
    return True


@dataclass
class Anomaly:
    """A semantic conflict between two rules in the same chain."""

    kind: str  # "shadowing" | "redundancy"
    chain: str
    severity: str  # critical | high | low
    rule_index: int
    rule_content: str
    related_index: int
    related_content: str
    description: str


def _severity_for_shadowing(shadower: ParsedRule, shadowed: ParsedRule) -> str:
    # An ACCEPT wiping out an intended DENY is the dangerous direction.
    if shadower.action == "ACCEPT" and shadowed.action in DENY_ACTIONS:
        return "critical"
    if shadower.action in DENY_ACTIONS and shadowed.action == "ACCEPT":
        return "high"
    return "medium"


def analyze_rules(rules: List[ParsedRule]) -> List[Anomaly]:
    """Detect shadowing and redundancy among parsed rules, per chain.

    O(n^2) pairwise comparison. For the configuration sizes in scope
    (hundreds to low thousands of rules) this is well within budget; if rule
    counts ever reach 10^5, index by (protocol, src) and prune with a trie.
    """
    anomalies: List[Anomaly] = []
    for i, later in enumerate(rules):
        for earlier in rules[:i]:
            if not covers(earlier, later):
                continue
            if earlier.action == later.action:
                anomalies.append(
                    Anomaly(
                        kind="redundancy",
                        chain=later.chain,
                        severity="low",
                        rule_index=later.index,
                        rule_content=later.raw,
                        related_index=earlier.index,
                        related_content=earlier.raw,
                        description=(
                            f"Redundant rule at line {later.line_number or later.index}: "
                            f"identical match already handled by earlier "
                            f"{earlier.action} rule (line "
                            f"{earlier.line_number or earlier.index})"
                        ),
                    )
                )
            else:
                anomalies.append(
                    Anomaly(
                        kind="shadowing",
                        chain=later.chain,
                        severity=_severity_for_shadowing(earlier, later),
                        rule_index=later.index,
                        rule_content=later.raw,
                        related_index=earlier.index,
                        related_content=earlier.raw,
                        description=(
                            f"Rule at line {later.line_number or later.index} "
                            f"({later.action}) is shadowed by earlier rule "
                            f"(line {earlier.line_number or earlier.index}, "
                            f"{earlier.action}) and can never match"
                        ),
                    )
                )
            # First (earliest) covering rule explains the anomaly; stop.
            break
    return anomalies


def analyze_config_items(config_items) -> Tuple[List[Anomaly], set]:
    """Analyze ``ConfigurationItem`` objects.

    Returns the anomalies plus the set of raw rule contents that are shadowed
    (used to mark a declared policy rule as ineffective even though it exists).
    """
    parsed: List[ParsedRule] = []
    for idx, item in enumerate(config_items):
        if getattr(item, "type", None) != "firewall_rule":
            continue
        pr = parse_rule(item.content, len(parsed), getattr(item, "line_number", None))
        if pr is not None:
            parsed.append(pr)

    anomalies = analyze_rules(parsed)
    shadowed_contents = {
        a.rule_content for a in anomalies if a.kind == "shadowing"
    }
    return anomalies, shadowed_contents


def _self_check() -> None:
    """Minimal runnable check: `python -m audit_agent.audit.anomaly`."""
    lines = [
        "-A INPUT -p tcp --dport 22 -j ACCEPT",
        "-A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j DROP",
        "-A INPUT -s 192.168.1.0/24 -p tcp --dport 443 -j ACCEPT",
        "-A INPUT -s 192.168.1.0/25 -p tcp --dport 443 -j ACCEPT",
    ]
    parsed = [parse_rule(line, i) for i, line in enumerate(lines)]
    parsed = [p for p in parsed if p is not None]
    anomalies = analyze_rules(parsed)

    shadowed = {a.rule_content for a in anomalies if a.kind == "shadowing"}
    assert lines[1] in shadowed, "broad ACCEPT should shadow the narrower DROP"
    assert all(
        a.severity == "critical"
        for a in anomalies
        if a.kind == "shadowing" and a.rule_content == lines[1]
    )
    redundant = {a.rule_content for a in anomalies if a.kind == "redundancy"}
    assert lines[3] in redundant, "/25 is redundant under earlier /24"
    # /25 must be recognised as contained by /24 (stdlib CIDR subsumption).
    assert parse_rule(lines[2], 0).src.supernet_of(parse_rule(lines[3], 0).src)
    print(f"ok: {len(anomalies)} anomalies, {len(shadowed)} shadowed")


if __name__ == "__main__":
    _self_check()
