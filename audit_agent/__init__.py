"""
AuditAgent - Linux iptables Policy Enforcer & Auditor

A Python framework for declaratively defining and enforcing iptables firewall
policies across Linux servers.
"""

from importlib.metadata import version

__version__ = version("audit-agent")
__author__ = "Your Name"
__email__ = "your.email@example.com"

from .audit.engine import AuditEngine
from .core.objects import IPAddress, IPRange, Port, Zone
from .core.policy import NetworkPolicy
from .core.rules import FirewallRule, NATRule, VPNRule
from .devices.linux_iptables import LinuxIptables
from .enforcement.engine import EnforcementEngine

__all__ = [
    "NetworkPolicy",
    "FirewallRule",
    "NATRule",
    "VPNRule",
    "IPRange",
    "IPAddress",
    "Port",
    "Zone",
    "AuditEngine",
    "EnforcementEngine",
    "LinuxIptables",
]
