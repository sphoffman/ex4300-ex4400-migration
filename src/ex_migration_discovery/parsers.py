from __future__ import annotations

import ipaddress
import re
import shlex
from collections import defaultdict
from datetime import datetime, timezone

from .model import (
    InterfaceState,
    MacObservation,
    ManagementProfile,
    SnmpIdentity,
    SourceAddress,
    VlanRef,
    VlanState,
    VoicePolicy,
)
from .normalize import classify_learning_interface, normalize_mac, split_interface


_SET_VLAN = re.compile(r"^set vlans (?P<name>\S+) vlan-id (?P<id>\d+)$")
_VLAN_DESCRIPTION = re.compile(r"^set vlans (?P<name>\S+) description (?P<value>.+)$")
_VLAN_IRB = re.compile(r"^set vlans (?P<name>\S+) l3-interface (?P<irb>\S+)$")
_VOICE = re.compile(r"^set switch-options voip interface (?P<selector>\S+) vlan (?P<vlan>\S+)$")
_AE_PARENT = re.compile(r"^set interfaces (?P<ifd>\S+) (?:gigether-options|ether-options) 802\.3ad (?P<ae>ae\d+)$")
_DESCRIPTION = re.compile(r'^set interfaces (?P<ifd>\S+) description "?(?P<desc>.*?)"?$')
_MODE = re.compile(r"^set interfaces (?P<ifd>\S+) unit (?P<unit>\d+) family ethernet-switching interface-mode (?P<mode>\S+)$")
_VLAN_MEMBER = re.compile(r"^set interfaces (?P<ifd>\S+) unit (?P<unit>\d+) family ethernet-switching vlan members (?P<vlan>\S+)$")
_RANGE_MEMBER = re.compile(r'^set interfaces interface-range (?P<range>\S+) member "?(?P<member>.*?)"?$')
_RANGE_MODE = re.compile(r"^set interfaces interface-range (?P<range>\S+) unit \d+ family ethernet-switching interface-mode (?P<mode>\S+)$")
_DHCP_TRUST = re.compile(r"^set vlans (?P<vlan>\S+) forwarding-options dhcp-security group \S+ interface (?P<if>\S+)$")


def _value(text: str) -> str:
    try:
        values = shlex.split(text)
        return " ".join(values) if values else ""
    except ValueError:
        return text.strip()


def parse_set_configuration(text: str) -> tuple[dict[str, InterfaceState], dict[str, VlanState], VoicePolicy, list[str]]:
    interfaces: dict[str, InterfaceState] = {}
    vlans: dict[str, VlanState] = {}
    warnings: list[str] = []
    voice = VoicePolicy()
    range_members: dict[str, list[str]] = defaultdict(list)
    range_modes: dict[str, str] = {}

    def ensure_interface(name: str) -> InterfaceState:
        physical = name.split(".", 1)[0]
        if physical not in interfaces:
            p = split_interface(physical)
            interfaces[physical] = InterfaceState(
                name=physical, physical_name=physical,
                media_type=p["media"] if isinstance(p["media"], str) else None,
                vc_member=p["member"] if isinstance(p["member"], int) else None,
                pic=p["pic"] if isinstance(p["pic"], int) else None,
                port=p["port"] if isinstance(p["port"], int) else None,
            )
        return interfaces[physical]

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("deactivate ", "inactive:")):
            continue
        if match := _SET_VLAN.match(line):
            name, vlan_id = match.group("name"), int(match.group("id"))
            vlan = vlans.setdefault(name, VlanState(name, vlan_id))
            vlan.vlan_id = vlan_id
        elif match := _VLAN_DESCRIPTION.match(line):
            name = match.group("name")
            vlans.setdefault(name, VlanState(name, None)).description = _value(match.group("value"))
        elif match := _VLAN_IRB.match(line):
            name = match.group("name")
            vlans.setdefault(name, VlanState(name, None)).irb_interface = match.group("irb")
        elif match := _VOICE.match(line):
            voice.configured = True
            voice.vlan_name = match.group("vlan")
            voice.interface_selectors.append(match.group("selector"))
            voice.evidence.append(line)
        elif match := _AE_PARENT.match(line):
            ensure_interface(match.group("ifd")).ae_parent = match.group("ae")
        elif match := _DESCRIPTION.match(line):
            ensure_interface(match.group("ifd")).description = match.group("desc").rstrip('"')
        elif match := _MODE.match(line):
            ensure_interface(match.group("ifd")).effective_mode = match.group("mode")
        elif match := _VLAN_MEMBER.match(line):
            state = ensure_interface(match.group("ifd"))
            vlan_name = match.group("vlan")
            if vlan_name != "all":
                state.untagged_vlan = VlanRef(vlan_name, vlans.get(vlan_name).vlan_id if vlan_name in vlans else None)
        elif match := _RANGE_MEMBER.match(line):
            range_members[match.group("range")].append(match.group("member"))
        elif match := _RANGE_MODE.match(line):
            range_modes[match.group("range")] = match.group("mode")
        elif match := _DHCP_TRUST.match(line):
            name = match.group("vlan")
            vlans.setdefault(name, VlanState(name, None)).dhcp_snooping_trusted_interfaces.append(match.group("if"))

    for range_name, members in range_members.items():
        for member in members:
            if re.fullmatch(r"[a-z]+-\d+/\d+/\d+", member):
                state = ensure_interface(member)
                state.interface_ranges.append(range_name)
                if state.effective_mode is None and range_name in range_modes:
                    state.effective_mode = range_modes[range_name]
            else:
                warnings.append(f"interface-range selector requires effective-config validation: {range_name}={member}")

    if voice.configured:
        vlan = vlans.get(voice.vlan_name or "")
        if vlan is None:
            voice.errors.append(f"voice VLAN {voice.vlan_name!r} is not defined")
        else:
            voice.vlan_id = vlan.vlan_id
            voice.valid = vlan.vlan_id is not None
    for state in interfaces.values():
        if state.untagged_vlan and state.untagged_vlan.name in vlans:
            state.untagged_vlan = VlanRef(state.untagged_vlan.name, vlans[state.untagged_vlan.name].vlan_id)
    return interfaces, vlans, voice, sorted(set(warnings))


def parse_management_configuration(
    text: str,
    vlans: dict[str, VlanState],
    policy_vlan_id: int,
    connection_address: str | None,
    snmp_v3_configured: bool | None,
) -> tuple[str | None, ManagementProfile]:
    configured_hostname = None
    snmp = SnmpIdentity(v3_configured=snmp_v3_configured)
    irb_addresses: dict[str, list[str]] = defaultdict(list)
    fxp0_addresses: list[str] = []
    default_gateway = None
    mgmt_gateways: list[str] = []
    raw_sources: list[tuple[str, str]] = []

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("deactivate ", "inactive:")):
            continue
        if line.startswith("set system host-name "):
            configured_hostname = _value(line[len("set system host-name ") :])
        elif line == "set snmp name hostname":
            snmp.name, snmp.name_uses_hostname = "hostname", True
        elif line.startswith("set snmp name "):
            snmp.name = _value(line[len("set snmp name ") :])
        elif line.startswith("set snmp location "):
            snmp.location = _value(line[len("set snmp location ") :])
        elif match := re.match(r"^set snmp engine-id (?P<kind>\S+) (?P<value>\S+)$", line):
            snmp.engine_id_type, snmp.engine_id = match.group("kind"), match.group("value")
        elif match := re.match(r"^set interfaces irb unit (?P<unit>\d+) family inet address (?P<address>\S+)$", line):
            irb_addresses[f"irb.{match.group('unit')}"] .append(match.group("address"))
        elif match := re.match(r"^set interfaces fxp0 unit \d+ family inet address (?P<address>\S+)$", line):
            fxp0_addresses.append(match.group("address"))
        elif match := re.match(r"^set routing-options static route 0\.0\.0\.0/0 next-hop (?P<gateway>\S+)$", line):
            default_gateway = match.group("gateway")
        elif match := re.match(r"^set routing-instances mgmt_junos routing-options static route 0\.0\.0\.0/0 next-hop (?P<gateway>\S+)$", line):
            mgmt_gateways.append(match.group("gateway"))
        elif match := re.match(r"^set (?P<path>.+?) source-address (?P<address>\S+)$", line):
            raw_sources.append((match.group("path") + " source-address", match.group("address")))

    matches = [v for v in vlans.values() if v.vlan_id == policy_vlan_id]
    findings: list[str] = []
    vlan = matches[0] if len(matches) == 1 else None
    if not matches:
        findings.append(f"management VLAN ID {policy_vlan_id} is not configured")
    elif len(matches) > 1:
        findings.append(f"management VLAN ID {policy_vlan_id} is configured under multiple names")
    l3_interface = vlan.irb_interface if vlan else None
    addresses = list(irb_addresses.get(l3_interface or "", []))
    production_ipv4 = None
    if len(addresses) == 1:
        try:
            production_ipv4 = str(ipaddress.ip_interface(addresses[0]).ip)
        except ValueError:
            findings.append(f"invalid management address {addresses[0]!r}")
    else:
        findings.append(f"management interface {l3_interface or 'unresolved'} has {len(addresses)} IPv4 addresses")

    sources: list[SourceAddress] = []
    for path, address in raw_sources:
        matches_ip = None if production_ipv4 is None else address == production_ipv4
        disposition = "UNRESOLVED" if matches_ip is None else "COPY_SAFE" if matches_ip else "REVIEW_REQUIRED"
        if matches_ip is False:
            findings.append(f"{path} uses {address}, not management IP {production_ipv4}")
        sources.append(SourceAddress(path, address, matches_ip, disposition))

    if vlan:
        vlan.purpose = "management"
    if vlan and not l3_interface:
        findings.append(f"management VLAN {vlan.name} has no l3-interface")
    if l3_interface and not re.fullmatch(rf"irb\.{policy_vlan_id}", l3_interface):
        findings.append(f"management VLAN {policy_vlan_id} references {l3_interface}")
    if snmp.engine_id and production_ipv4 and snmp.engine_id != production_ipv4:
        findings.append(f"SNMP engine ID {snmp.engine_id} does not match management IP {production_ipv4}")
    if default_gateway and addresses:
        try:
            if ipaddress.ip_address(default_gateway) not in ipaddress.ip_interface(addresses[0]).network:
                findings.append(f"default gateway {default_gateway} is not on management subnet {addresses[0]}")
        except ValueError:
            findings.append("management address or default gateway is invalid")

    consistency = "CONSISTENT" if not findings else "REVIEW_REQUIRED"
    return configured_hostname, ManagementProfile(
        policy_vlan_id=policy_vlan_id,
        vlan_name=vlan.name if vlan else None,
        vlan_id=vlan.vlan_id if vlan else None,
        l3_interface=l3_interface,
        addresses=addresses,
        production_ipv4=production_ipv4,
        default_gateway=default_gateway,
        connection_address=connection_address,
        fxp0_addresses=fxp0_addresses,
        mgmt_junos_default_gateways=mgmt_gateways,
        snmp=snmp,
        source_addresses=sources,
        consistency=consistency,
        findings=sorted(set(findings)),
    )


_MAC_BLOCK = re.compile(r"MAC address:\s*(?P<mac>\S+)(?P<body>.*?)(?=\nMAC address:|\Z)", re.DOTALL)


def parse_mac_table_text(text: str, observed_at: str | None, raw_artifact: str, interfaces: dict[str, InterfaceState] | None = None) -> list[MacObservation]:
    timestamp = observed_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    results: list[MacObservation] = []
    for block in _MAC_BLOCK.finditer(text):
        body = block.group("body")
        ri = _find(body, r"Routing instance:\s*(\S+)")
        vlan_match = re.search(r"VLAN name:\s*([^,\n]+),\s*VLAN ID:\s*(\d+)", body)
        learned = _find(body, r"Learning interface:\s*(\S+)")
        if not vlan_match or not learned:
            continue
        parsed = split_interface(learned)
        flags = _find(body, r"Layer 2 flags:\s*([^\n]+)") or ""
        mac_type = "static" if "static" in flags and "non configured static" not in flags else "dynamic"
        results.append(MacObservation(timestamp, normalize_mac(block.group("mac")), ri, VlanRef(vlan_match.group(1).strip(), int(vlan_match.group(2))), learned, str(parsed["physical"]), parsed["unit"] if isinstance(parsed["unit"], int) else None, classify_learning_interface(learned, interfaces), mac_type, raw_artifact))
    return results


def parse_interfaces_descriptions(text: str, interfaces: dict[str, InterfaceState]) -> None:
    for line in text.splitlines():
        match = re.match(r"^(?P<name>[a-z]+-\d+/\d+/\d+)\s+(?P<admin>up|down)\s+(?P<link>up|down)\s*(?P<desc>.*)$", line.strip())
        if not match:
            continue
        state = interfaces.setdefault(match.group("name"), InterfaceState(match.group("name"), match.group("name")))
        state.admin_status, state.oper_status = match.group("admin"), match.group("link")
        if match.group("desc"):
            state.description = match.group("desc")


def parse_interfaces_terse(text: str, interfaces: dict[str, InterfaceState]) -> set[str]:
    present: set[str] = set()
    for line in text.splitlines():
        match = re.match(r"^(?P<name>(?:(?:ge|xe|et|mge)-\d+/\d+/\d+|ae\d+))\s+(?P<admin>up|down)\s+(?P<link>up|down)(?:\s|$)", line.strip())
        if not match:
            continue
        name = match.group("name"); present.add(name); p = split_interface(name)
        state = interfaces.setdefault(name, InterfaceState(name=name, physical_name=name, media_type=p["media"] if isinstance(p["media"], str) else None, vc_member=p["member"] if isinstance(p["member"], int) else None, pic=p["pic"] if isinstance(p["pic"], int) else None, port=p["port"] if isinstance(p["port"], int) else None))
        state.admin_status, state.oper_status = match.group("admin"), match.group("link")
    return present


def parse_lldp_neighbors_text(text: str, observed_at: str, raw_artifact: str) -> list[dict]:
    result=[]
    for block in text.split("LLDP Neighbor Information:")[1:]:
        local=_find(block,r"Local Interface\s*:\s*(\S+)"); system=_find(block,r"System name\s*:\s*([^\n]+)"); port=_find(block,r"Port ID\s*:\s*(\S+)"); parent=_find(block,r"Parent Interface\s*:\s*(\S+)")
        if local and system:
            result.append({"observed_at":observed_at,"local_interface":local,"parent_interface":None if parent=="-" else parent,"remote_system_name":system,"remote_port_id":port,"raw_artifact":raw_artifact})
    return result


def _find(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else None
