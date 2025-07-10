"""
Base classes for network device abstraction.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from pydantic import BaseModel
from ..core.rules import BaseRule


class DeviceCredentials(BaseModel):
    """Credentials for device authentication."""

    username: Optional[str] = None
    password: Optional[str] = None
    private_key: Optional[str] = None
    api_key: Optional[str] = None
    token: Optional[str] = None


class DeviceConnection(BaseModel):
    """Device connection information."""

    host: str
    port: Optional[int] = None
    protocol: str = "ssh"  # ssh, https, telnet, etc.
    timeout: int = 30
    credentials: DeviceCredentials


class DeviceInfo(BaseModel):
    """Information about a network device."""

    hostname: str
    vendor: str
    model: str
    version: str
    serial_number: Optional[str] = None
    interfaces: List[str] = []
    zones: List[str] = []


class ConfigurationItem(BaseModel):
    """Represents a configuration item on a device."""

    type: str  # "firewall_rule", "nat_rule", etc.
    content: str
    line_number: Optional[int] = None
    section: Optional[str] = None
    raw_config: str


class DeviceConfiguration(BaseModel):
    """Complete configuration of a device."""

    device_info: DeviceInfo
    raw_config: str
    parsed_items: List[ConfigurationItem] = []
    timestamp: str

    def get_items_by_type(self, item_type: str) -> List[ConfigurationItem]:
        """Get configuration items of a specific type."""
        return [item for item in self.parsed_items if item.type == item_type]


class CommandResult(BaseModel):
    """Result of executing a command on a device."""

    command: str
    success: bool
    output: str
    error: Optional[str] = None
    exit_code: Optional[int] = None
    execution_time: float


class NetworkDevice(ABC):
    """
    Abstract base class for all network devices.

    This class defines the interface that all device implementations must follow.
    """

    model_config = {"arbitrary_types_allowed": True}

    def __init__(self, connection: DeviceConnection):
        self.connection = connection
        self._connected = False
        self._device_info: Optional[DeviceInfo] = None

    @property
    def is_connected(self) -> bool:
        """Check if device is currently connected."""
        return self._connected

    @property
    def device_info(self) -> Optional[DeviceInfo]:
        """Get device information."""
        return self._device_info

    @abstractmethod
    async def connect(self) -> bool:
        """Connect to the device."""
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from the device."""
        pass

    @abstractmethod
    async def execute_command(self, command: str) -> CommandResult:
        """Execute a command on the device."""
        pass

    @abstractmethod
    async def get_configuration(self) -> DeviceConfiguration:
        """Get the current device configuration."""
        pass

    @abstractmethod
    async def get_device_info(self) -> DeviceInfo:
        """Get device information."""
        pass

    @abstractmethod
    def parse_configuration(self, raw_config: str) -> List[ConfigurationItem]:
        """Parse raw configuration into structured items."""
        pass

    @abstractmethod
    def rule_to_commands(self, rule: BaseRule) -> List[str]:
        """Convert a rule to device-specific commands."""
        pass

    @abstractmethod
    def validate_commands(self, commands: List[str]) -> List[str]:
        """Validate commands before execution. Returns any validation errors."""
        pass

    @abstractmethod
    async def apply_commands(
        self, commands: List[str], dry_run: bool = False
    ) -> List[CommandResult]:
        """Apply commands to the device."""
        pass

    async def backup_configuration(self) -> str:
        """Create a backup of the current configuration."""
        config = await self.get_configuration()
        return config.raw_config

    async def test_connectivity(self) -> bool:
        """Test basic connectivity to the device."""
        try:
            if not self.is_connected:
                await self.connect()
            # Try a simple command
            result = await self.execute_command(self.get_test_command())
            return result.success
        except Exception:
            return False

    @abstractmethod
    def get_test_command(self) -> str:
        """Get a simple command to test connectivity."""
        pass

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.connection.host})"

    def __repr__(self) -> str:
        return self.__str__()


class FirewallDevice(NetworkDevice):
    """Base class for firewall devices."""

    @abstractmethod
    async def get_firewall_rules(self) -> List[ConfigurationItem]:
        """Get all firewall rules from the device."""
        pass

    @abstractmethod
    async def get_nat_rules(self) -> List[ConfigurationItem]:
        """Get all NAT rules from the device."""
        pass

    @abstractmethod
    async def get_zones(self) -> List[str]:
        """Get all security zones from the device."""
        pass


class RouterDevice(NetworkDevice):
    """Base class for router devices."""

    @abstractmethod
    async def get_routing_table(self) -> List[ConfigurationItem]:
        """Get routing table from the device."""
        pass

    @abstractmethod
    async def get_acls(self) -> List[ConfigurationItem]:
        """Get Access Control Lists from the device."""
        pass


class LoadBalancerDevice(NetworkDevice):
    """Base class for load balancer devices."""

    @abstractmethod
    async def get_virtual_servers(self) -> List[ConfigurationItem]:
        """Get virtual servers configuration."""
        pass

    @abstractmethod
    async def get_pools(self) -> List[ConfigurationItem]:
        """Get server pools configuration."""
        pass


class DeviceManager:
    """Manages multiple network devices."""

    def __init__(self):
        self.devices: List[NetworkDevice] = []

    def add_device(self, device: NetworkDevice) -> None:
        """Add a device to manage."""
        self.devices.append(device)

    def remove_device(self, device: NetworkDevice) -> None:
        """Remove a device from management."""
        if device in self.devices:
            self.devices.remove(device)

    def get_devices_by_type(self, device_type: type) -> List[NetworkDevice]:
        """Get devices of a specific type."""
        return [device for device in self.devices if isinstance(device, device_type)]

    async def connect_all(self) -> Dict[NetworkDevice, bool]:
        """Connect to all devices."""
        results = {}
        for device in self.devices:
            try:
                results[device] = await device.connect()
            except Exception:
                results[device] = False
        return results

    async def disconnect_all(self) -> None:
        """Disconnect from all devices."""
        for device in self.devices:
            try:
                await device.disconnect()
            except Exception:
                pass

    async def test_all_connectivity(self) -> Dict[NetworkDevice, bool]:
        """Test connectivity to all devices."""
        results = {}
        for device in self.devices:
            results[device] = await device.test_connectivity()
        return results
