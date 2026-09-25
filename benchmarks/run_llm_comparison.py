"""Comparative benchmark: AuditAgent vs. a raw LLM on drifted configurations.

For each scenario the harness asks the raw LLM for an iptables remediation,
then parses every command it produces through AuditAgent's own deterministic
gate/schema. A response counts as *valid* only if every command parses as an
`iptables` command that passes `validate_commands`. Anything else - shell
wrappers, prose, hallucinated flags on a non-iptables binary, malformed
syntax - is counted as invalid.

The point of the comparison is not that a raw LLM is worse at prose; it is
that the raw LLM has no deterministic pre-flight gate, so its output is not
safe to execute until AuditAgent parses it.

Usage::

    export OPENAI_API_KEY=...        # or ANTHROPIC_API_KEY
    python -m benchmarks.run_llm_comparison --scenarios 50 --provider openai
    python -m benchmarks.run_llm_comparison --dry-run   # no API call

Without an API key the script exits with a clear message rather than
silently producing empty results.
"""

from __future__ import annotations

import argparse
import json
import os
import random
from dataclasses import asdict, dataclass
from typing import Callable, Dict, List

from audit_agent.devices.linux_iptables import LinuxIptables, validate_command_safety

from .synthetic import COMMON_PORTS, _random_network

SYSTEM_PROMPT = (
    "You are a firewall administrator. Given a drifted Linux iptables rule "
    "set and the intended policy, output ONLY the iptables commands needed to "
    "fix the configuration, one per line. No explanation, no markdown."
)


@dataclass
class Scenario:
    id: int
    drift: str
    intended: str
    device_rules: List[str]

    def prompt(self) -> str:
        return (
            f"Intended policy: {self.intended}\n"
            f"Drift type: {self.drift}\n"
            f"Current rules:\n" + "\n".join(self.device_rules)
        )


DRIFTS = ["missing_rule", "shadowed_rule", "wrong_port", "wrong_action", "redundant_rule"]


def build_scenarios(count: int, seed: int = 0) -> List[Scenario]:
    rng = random.Random(seed)
    scenarios = []
    for i in range(count):
        drift = DRIFTS[i % len(DRIFTS)]
        src = _random_network(rng)
        port = COMMON_PORTS[i % len(COMMON_PORTS)]
        intended = f"allow {src} to tcp/{port}"
        rules = [f"-A INPUT -p tcp -s {src} --dport {port} -j ACCEPT"]
        if drift == "shadowing":
            rules.insert(0, "-A INPUT -j ACCEPT")
        elif drift == "missing_rule":
            rules = []
        elif drift == "wrong_port":
            rules = [f"-A INPUT -p tcp -s {src} --dport {port + 1} -j ACCEPT"]
        elif drift == "wrong_action":
            rules = [f"-A INPUT -p tcp -s {src} --dport {port} -j DROP"]
        elif drift == "redundant_rule":
            rules = [
                f"-A INPUT -p tcp -s {src} --dport {port} -j ACCEPT",
                f"-A INPUT -p tcp -s {src} --dport {port} -j ACCEPT",
            ]
        scenarios.append(
            Scenario(id=i, drift=drift, intended=intended, device_rules=rules)
        )
    return scenarios


def _openai(prompt: str, model: str) -> str:
    import urllib.request

    payload = json.dumps(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
        }
    ).encode()
    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed API host
        body = json.loads(response.read())
    return body["choices"][0]["message"]["content"]


def _anthropic(prompt: str, model: str) -> str:
    import urllib.request

    payload = json.dumps(
        {
            "model": model,
            "max_tokens": 1024,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        }
    ).encode()
    request = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed API host
        body = json.loads(response.read())
    return "".join(block["text"] for block in body["content"])


PROVIDERS: Dict[str, Callable[[str, str], str]] = {
    "openai": _openai,
    "anthropic": _anthropic,
}


class CommandRejector(LinuxIptables):
    """Device used only for its deterministic `validate_commands`."""

    def __init__(self):
        super().__init__(host="validator", username="validator")


def classify(raw: str) -> Dict:
    """Grade a raw LLM response with the deterministic gate."""
    device = CommandRejector()
    commands = [line.strip() for line in raw.splitlines() if line.strip()]
    invalid = []
    for command in commands:
        safety = validate_command_safety(command)
        if safety:
            invalid.append((command, safety))
            continue
        errors = device.validate_commands([command])
        if errors:
            invalid.append((command, errors[0]))
    if not commands:
        invalid.append(("<empty response>", "no commands produced"))
    return {
        "commands": commands,
        "invalid": invalid,
        "valid": not invalid,
    }


def run(scenarios: List[Scenario], provider: str, model: str, call: Callable) -> Dict:
    results = []
    for scenario in scenarios:
        raw = call(scenario.prompt(), model)
        grade = classify(raw)
        results.append(
            {
                "scenario": asdict(scenario),
                "raw_response": raw,
                "valid": grade["valid"],
                "invalid": grade["invalid"],
            }
        )

    total = len(results)
    valid = sum(1 for r in results if r["valid"])
    by_drift: Dict[str, Dict[str, int]] = {}
    for r in results:
        drift = r["scenario"]["drift"]
        bucket = by_drift.setdefault(drift, {"total": 0, "valid": 0})
        bucket["total"] += 1
        bucket["valid"] += int(r["valid"])

    return {
        "provider": provider,
        "model": model,
        "total": total,
        "valid": valid,
        "invalid": total - valid,
        "valid_rate": (valid / total * 100) if total else 0.0,
        "by_drift": by_drift,
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=int, default=50)
    parser.add_argument("--provider", choices=sorted(PROVIDERS), default="openai")
    parser.add_argument("--model", type=str, default=None)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--json", type=str, default="llm_comparison.json")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="use a canned raw-LLM-style response instead of calling an API",
    )
    args = parser.parse_args()

    defaults = {"openai": "gpt-4o", "anthropic": "claude-3-5-sonnet-20241022"}
    model = args.model or defaults[args.provider]

    scenarios = build_scenarios(args.scenarios, seed=args.seed)

    if args.dry_run:
        good = "iptables -A INPUT -p tcp --dport 22 -j ACCEPT"

        def canned_call(prompt: str, _model: str) -> str:
            # Deterministically mix clean output with the failure modes a raw
            # LLM actually exhibits: shell chaining, markdown fences, prose.
            if "shadowed_rule" in prompt:
                return "```bash\n" + good + "\n```"
            if "wrong_action" in prompt:
                return good + "; iptables -F INPUT"
            if "missing_rule" in prompt:
                return "I cannot safely modify firewall rules without more context."
            return good

        summary = run(scenarios, args.provider, model, canned_call)
    else:
        env_var = "OPENAI_API_KEY" if args.provider == "openai" else "ANTHROPIC_API_KEY"
        if not os.environ.get(env_var):
            raise SystemExit(
                f"{env_var} not set. Export it, or pass --dry-run for a canned run."
            )
        summary = run(scenarios, args.provider, model, PROVIDERS[args.provider])

    print(
        f"\n{summary['model']}: {summary['valid']}/{summary['total']} responses "
        f"survived the deterministic gate ({summary['valid_rate']:.1f}%)"
    )
    print("\n| drift | valid | total |")
    print("|-------|-------|-------|")
    for drift, bucket in sorted(summary["by_drift"].items()):
        print(f"| {drift} | {bucket['valid']} | {bucket['total']} |")

    with open(args.json, "w") as handle:
        json.dump(summary, handle, indent=2)
    print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
