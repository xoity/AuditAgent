"""Scalability harness: audit time and memory vs. rule-set size.

Feeds the paper's scalability tables. For each size it builds a policy and a
device configuration of that many rules, runs a full audit, and records wall
time and peak RSS delta. Also times the semantic anomaly pass in isolation,
since that is the component we claim scales.

Usage::

    python -m benchmarks.run_scalability                 # 100..10000
    python -m benchmarks.run_scalability --sizes 100 500 # custom
    python -m benchmarks.run_scalability --repeat 5 --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import json
import resource
import statistics
import threading
import time
from typing import Dict, List

from audit_agent.audit.anomaly import analyze_rules, parse_rule
from audit_agent.audit.engine import AuditEngine
from audit_agent.devices.base import ConfigurationItem

from .synthetic import generate_device_lines, generate_policy

DEFAULT_SIZES = [100, 500, 1000, 5000, 10000]


def _rss_kb() -> int:
    # ru_maxrss is KB on Linux; use current RSS via /proc for a delta-friendly
    # reading, falling back to ru_maxrss where /proc is unavailable.
    try:
        with open("/proc/self/status") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def _items(lines: List[str]) -> List[ConfigurationItem]:
    return [
        ConfigurationItem(
            type="firewall_rule",
            content=line,
            line_number=i + 1,
            section="filter:INPUT",
            raw_config="",
        )
        for i, line in enumerate(lines)
    ]


class _Device:
    """Minimal in-process device returning a fixed configuration."""

    def __init__(self, items):
        self._items = items
        self._connected = True

    @property
    def is_connected(self):
        return True

    async def connect(self):
        return True

    async def get_configuration(self):
        from audit_agent.devices.base import DeviceConfiguration, DeviceInfo

        return DeviceConfiguration(
            device_info=DeviceInfo(
                hostname="bench", vendor="bench", model="bench", version="1"
            ),
            raw_config="",
            parsed_items=self._items,
            timestamp="",
        )

    def __str__(self):
        return "bench-device"


async def _time_audit(size: int, seed: int) -> float:
    policy = generate_policy(size, seed=seed)
    device = _Device(_items(generate_device_lines(size, seed=seed)))
    start = time.perf_counter()
    await AuditEngine().audit_device(policy, device)
    return time.perf_counter() - start


def _time_audit_with_peak(size: int, seed: int) -> tuple[float, int]:
    baseline = _rss_kb()
    peak = baseline
    done = threading.Event()

    def sample() -> None:
        nonlocal peak
        while not done.wait(0.001):
            peak = max(peak, _rss_kb())

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    try:
        elapsed = asyncio.run(_time_audit(size, seed))
        peak = max(peak, _rss_kb())
    finally:
        done.set()
        sampler.join()
    return elapsed, peak - baseline


def _time_anomaly(size: int, seed: int) -> float:
    parsed = [
        parse_rule(line, i)
        for i, line in enumerate(generate_device_lines(size, seed=seed))
    ]
    parsed = [p for p in parsed if p is not None]
    start = time.perf_counter()
    analyze_rules(parsed)
    return time.perf_counter() - start


def run(sizes: List[int], repeat: int, seed: int) -> List[Dict[str, float]]:
    if repeat <= 0:
        raise ValueError("repeat must be positive")

    rows = []
    for size in sizes:
        gc.collect()
        audit_times = []
        peak_deltas = []
        for _ in range(repeat):
            elapsed, peak_delta = _time_audit_with_peak(size, seed)
            audit_times.append(elapsed)
            peak_deltas.append(peak_delta)
        anomaly_times = [_time_anomaly(size, seed) for _ in range(repeat)]

        rows.append(
            {
                "rules": size,
                "audit_s_mean": statistics.mean(audit_times),
                "audit_s_stdev": statistics.stdev(audit_times)
                if len(audit_times) > 1
                else 0.0,
                "anomaly_s_mean": statistics.mean(anomaly_times),
                "rss_delta_kb": max(peak_deltas),
                "repeat": repeat,
            }
        )
        print(
            f"rules={size:>6}  audit={rows[-1]['audit_s_mean']:.4f}s"
            f"  anomaly={rows[-1]['anomaly_s_mean']:.4f}s"
            f"  rss_delta={rows[-1]['rss_delta_kb']}KB"
        )
    return rows


def main() -> None:
    def positive_int(value: str) -> int:
        parsed = int(value)
        if parsed <= 0:
            raise argparse.ArgumentTypeError("must be positive")
        return parsed

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=DEFAULT_SIZES)
    parser.add_argument("--repeat", type=positive_int, default=3)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--json", type=str, default=None, help="write raw rows to JSON")
    args = parser.parse_args()

    rows = run(args.sizes, args.repeat, args.seed)

    print("\n| rules | audit (s) | anomaly (s) | RSS delta (KB) |")
    print("|-------|-----------|-------------|----------------|")
    for row in rows:
        print(
            f"| {row['rules']} | {row['audit_s_mean']:.4f} | "
            f"{row['anomaly_s_mean']:.4f} | {row['rss_delta_kb']} |"
        )

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(rows, handle, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
