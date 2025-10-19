"""
Core network objects for representing IPs, ports, zones, and other network entities.
"""

import re
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from typing import ClassVar, List, Optional, Union

from pydantic import BaseModel, validator


class IPAddress(BaseModel):
    model_config = {"arbitrary_types_allowed": True}
    """Represents a single IP address."""

    address: str

    @validator("address")
    def validate_ip(cls, v):
        try:
            IPv4Address(v)
            return v
        except AddressValueError:
            raise ValueError(f"Invalid IP address: {v}")

    def __str__(self) -> str:
        return self.address


class IPRange(BaseModel):
    model_config = {"arbitrary_types_allowed": True}
    """Represents an IP address range or CIDR block."""

    cidr: str

    @validator("cidr")
    def validate_cidr(cls, v):
        try:
            IPv4Network(v, strict=False)
            return v
        except AddressValueError:
            raise ValueError(f"Invalid CIDR notation: {v}")

    def contains(self, ip: Union[str, IPAddress]) -> bool:
        """Check if the given IP is within this range."""
        target_ip = str(ip) if isinstance(ip, IPAddress) else ip
        try:
            return IPv4Address(target_ip) in IPv4Network(self.cidr)
        except AddressValueError:
            return False

    def __str__(self) -> str:
        return self.cidr


class Port(BaseModel):
    model_config = {"arbitrary_types_allowed": True}
    """Represents a network port or port range."""

    number: Optional[int] = None
    range_start: Optional[int] = None
    range_end: Optional[int] = None
    name: Optional[str] = None  # Named ports like 'ssh', 'http', 'https'

    @validator("number")
    def validate_port_number(cls, v):
        if v is not None and (v < 1 or v > 65535):
            raise ValueError(f"Port number must be between 1 and 65535, got {v}")
        return v

    @validator("range_start", "range_end")
    def validate_port_range(cls, v):
        if v is not None and (v < 1 or v > 65535):
            raise ValueError(f"Port range must be between 1 and 65535, got {v}")
        return v

    def __post_init__(self):
        if self.range_start and self.range_end:
            if self.range_start > self.range_end:
                raise ValueError("range_start must be less than or equal to range_end")

    @classmethod
    def single(cls, port: int) -> "Port":
        """Create a single port."""
        return cls(number=port)

    @classmethod
    def range(cls, start: int, end: int) -> "Port":
        """Create a port range."""
        return cls(range_start=start, range_end=end)

    @classmethod
    def named(cls, name: str) -> "Port":
        """Create a named port."""
        return cls(name=name)

    def is_range(self) -> bool:
        """Check if this is a port range."""
        return self.range_start is not None and self.range_end is not None

    def is_single(self) -> bool:
        """Check if this is a single port."""
        return self.number is not None

    def is_named(self) -> bool:
        """Check if this is a named port."""
        return self.name is not None

    def __str__(self) -> str:
        if self.is_single():
            return str(self.number)
        elif self.is_range():
            return f"{self.range_start}-{self.range_end}"
        elif self.is_named():
            return self.name or "unnamed"
        return "any"


class Zone(BaseModel):
    model_config = {"arbitrary_types_allowed": True}
    """Represents a network zone or security zone."""

    name: str
    description: Optional[str] = None
    networks: List[IPRange] = []

    @validator("name")
    def validate_zone_name(cls, v):
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError(
                f"Zone name must contain only alphanumeric characters, hyphens, and underscores: {v}"
            )
        return v

    def add_network(self, network: Union[str, IPRange]) -> None:
        """Add a network to this zone."""
        if isinstance(network, str):
            network = IPRange(cidr=network)
        self.networks.append(network)

    def contains_ip(self, ip: Union[str, IPAddress]) -> bool:
        """Check if the given IP is within any network in this zone."""
        return any(network.contains(ip) for network in self.networks)

    def __str__(self) -> str:
        return self.name


class Protocol(BaseModel):
    model_config = {"arbitrary_types_allowed": True}
    """Represents a network protocol."""

    name: str
    number: Optional[int] = None

    # Common protocols
    TCP: ClassVar[str] = "tcp"
    UDP: ClassVar[str] = "udp"
    ICMP: ClassVar[str] = "icmp"
    ANY: ClassVar[str] = "any"

    @validator("name")
    def validate_protocol_name(cls, v):
        valid_protocols = ["tcp", "udp", "icmp", "esp", "ah", "gre", "any"]
        if v.lower() not in valid_protocols:
            # Allow numeric protocols
            try:
                num = int(v)
                if 0 <= num <= 255:
                    return v
            except ValueError:
                pass
            raise ValueError(
                f"Invalid protocol: {v}. Must be one of {valid_protocols} or a number 0-255"
            )
        return v.lower()

    @classmethod
    def tcp(cls) -> "Protocol":
        return cls(name="tcp", number=6)

    @classmethod
    def udp(cls) -> "Protocol":
        return cls(name="udp", number=17)

    @classmethod
    def icmp(cls) -> "Protocol":
        return cls(name="icmp", number=1)

    @classmethod
    def any_protocol(cls) -> "Protocol":
        return cls(name="any")

    def __str__(self) -> str:
        return self.name


class Service(BaseModel):
    model_config = {"arbitrary_types_allowed": True}
    """Represents a network service with protocol and port(s)."""

    name: str
    protocol: Protocol
    ports: List[Port]
    description: Optional[str] = None

    @classmethod
    def ssh(cls) -> "Service":
        return cls(
            name="ssh",
            protocol=Protocol.tcp(),
            ports=[Port.single(22)],
            description="Secure Shell",
        )

    @classmethod
    def http(cls) -> "Service":
        return cls(
            name="http",
            protocol=Protocol.tcp(),
            ports=[Port.single(80)],
            description="HTTP Web Traffic",
        )

    @classmethod
    def https(cls) -> "Service":
        return cls(
            name="https",
            protocol=Protocol.tcp(),
            ports=[Port.single(443)],
            description="HTTPS Web Traffic",
        )

    @classmethod
    def dns(cls) -> "Service":
        return cls(
            name="dns",
            protocol=Protocol.udp(),
            ports=[Port.single(53)],
            description="Domain Name System",
        )

    def __str__(self) -> str:
        return self.name
