from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SCHEMA_VERSION = "1.1"


@dataclass(frozen=True)
class VlanRef:
    name: str | None
    vlan_id: int | None


@dataclass(frozen=True)
class MacObservation:
    observed_at: str
    mac: str
    routing_instance: str | None
    vlan: VlanRef
    reported_interface: str
    physical_interface: str
    unit: int | None
    interface_class: str
    mac_type: str
    raw_artifact: str


@dataclass
class InterfaceState:
    name: str
    physical_name: str
    unit: int | None = None
    media_type: str | None = None
    vc_member: int | None = None
    pic: int | None = None
    port: int | None = None
    admin_status: str | None = None
    oper_status: str | None = None
    description: str | None = None
    ae_parent: str | None = None
    effective_mode: str | None = None
    untagged_vlan: VlanRef | None = None
    tagged_vlans: list[VlanRef] = field(default_factory=list)
    interface_ranges: list[str] = field(default_factory=list)


@dataclass
class VlanState:
    name: str
    vlan_id: int | None
    configured: bool = True
    interfaces: list[dict[str, Any]] = field(default_factory=list)
    observed_mac_count: int = 0
    irb_interface: str | None = None
    dhcp_snooping_trusted_interfaces: list[str] = field(default_factory=list)


@dataclass
class VoicePolicy:
    configured: bool = False
    vlan_name: str | None = None
    vlan_id: int | None = None
    interface_selectors: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    valid: bool = False
    errors: list[str] = field(default_factory=list)


@dataclass
class DeviceIdentity:
    hostname: str | None = None
    model: str | None = None
    junos_version: str | None = None
    junos_family: str | None = None
    serial_numbers: list[str] = field(default_factory=list)


@dataclass
class Snapshot:
    snapshot_id: str
    migration_id: str
    device_role: str
    started_at: str
    completed_at: str
    lifecycle: str
    device: DeviceIdentity
    collection_policy: dict[str, Any]
    capabilities: dict[str, str]
    virtual_chassis: dict[str, Any]
    interfaces: list[InterfaceState]
    vlans: list[VlanState]
    voice_policy: VoicePolicy
    mac_observations: list[MacObservation]
    lldp_neighbors: list[dict[str, Any]]
    raw_artifacts: list[dict[str, Any]]
    warnings: list[str]
    errors: list[dict[str, Any]]
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
