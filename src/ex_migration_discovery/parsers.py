from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone

from .model import InterfaceState, MacObservation, VlanRef, VlanState, VoicePolicy
from .normalize import classify_learning_interface, normalize_mac, split_interface


_SET_VLAN = re.compile(r"^set vlans (?P<name>\S+) vlan-id (?P<id>\d+)$")
_VOICE = re.compile(
    r"^set switch-options voip interface (?P<selector>\S+) vlan (?P<vlan>\S+)$"
)
_AE_PARENT = re.compile(
    r"^set interfaces (?P<ifd>\S+) (?:gigether-options|ether-options) 802\.3ad (?P<ae>ae\d+)$"
)
_DESCRIPTION = re.compile(r'^set interfaces (?P<ifd>\S+) description "?(?P<desc>.*?)"?$')
_MODE = re.compile(
    r"^set interfaces (?P<ifd>\S+) unit (?P<unit>\d+) family ethernet-switching interface-mode (?P<mode>\S+)$"
)
_VLAN_MEMBER = re.compile(
    r"^set interfaces (?P<ifd>\S+) unit (?P<unit>\d+) family ethernet-switching vlan members (?P<vlan>\S+)$"
)
_RANGE_MEMBER = re.compile(r'^set interfaces interface-range (?P<range>\S+) member "?(?P<member>.*?)"?$')
_RANGE_MODE = re.compile(
    r"^set interfaces interface-range (?P<range>\S+) unit \d+ family ethernet-switching interface-mode (?P<mode>\S+)$"
)
_DHCP_TRUST = re.compile(
    r"^set vlans (?P<vlan>\S+) forwarding-options dhcp-security group \S+ interface (?P<if>\S+)$"
)


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
                name=physical,
                physical_name=physical,
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
            vlan_id = int(match.group("id"))
            vlans[match.group("name")] = VlanState(match.group("name"), vlan_id)
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
                ref = VlanRef(vlan_name, vlans.get(vlan_name).vlan_id if vlan_name in vlans else None)
                state.untagged_vlan = ref
        elif match := _RANGE_MEMBER.match(line):
            range_members[match.group("range")].append(match.group("member"))
        elif match := _RANGE_MODE.match(line):
            range_modes[match.group("range")] = match.group("mode")
        elif match := _DHCP_TRUST.match(line):
            vlan = vlans.setdefault(match.group("vlan"), VlanState(match.group("vlan"), None))
            vlan.dhcp_snooping_trusted_interfaces.append(match.group("if"))

    # Range regex expansion is intentionally conservative. Exact physical members
    # are applied; regex selectors are retained as evidence for later effective-
    # configuration RPC processing rather than guessed locally.
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


_MAC_BLOCK = re.compile(
    r"MAC address:\s*(?P<mac>\S+)(?P<body>.*?)(?=\nMAC address:|\Z)",
    re.DOTALL,
)


def parse_mac_table_text(
    text: str,
    observed_at: str | None,
    raw_artifact: str,
    interfaces: dict[str, InterfaceState] | None = None,
) -> list[MacObservation]:
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
        results.append(
            MacObservation(
                observed_at=timestamp,
                mac=normalize_mac(block.group("mac")),
                routing_instance=ri,
                vlan=VlanRef(vlan_match.group(1).strip(), int(vlan_match.group(2))),
                reported_interface=learned,
                physical_interface=str(parsed["physical"]),
                unit=parsed["unit"] if isinstance(parsed["unit"], int) else None,
                interface_class=classify_learning_interface(learned, interfaces),
                mac_type=mac_type,
                raw_artifact=raw_artifact,
            )
        )
    return results


def parse_interfaces_descriptions(text: str, interfaces: dict[str, InterfaceState]) -> None:
    for line in text.splitlines():
        match = re.match(r"^(?P<name>[a-z]+-\d+/\d+/\d+)\s+(?P<admin>up|down)\s+(?P<link>up|down)\s*(?P<desc>.*)$", line.strip())
        if not match:
            continue
        state = interfaces.setdefault(match.group("name"), InterfaceState(match.group("name"), match.group("name")))
        state.admin_status = match.group("admin")
        state.oper_status = match.group("link")
        if match.group("desc"):
            state.description = match.group("desc")

def parse_interfaces_terse(text: str, interfaces: dict[str, InterfaceState]) -> set[str]:
    present: set[str] = set()
    for line in text.splitlines():
        match = re.match(r"^(?P<name>(?:[a-z]+-\d+/\d+/\d+|ae\d+))\s+(?P<admin>up|down)\s+(?P<link>up|down)(?:\s|$)", line.strip())
        if not match:
            continue
        name = match.group("name")
        present.add(name)
        p = split_interface(name)
        state = interfaces.setdefault(name, InterfaceState(name=name, physical_name=name, media_type=p["media"] if isinstance(p["media"], str) else None, vc_member=p["member"] if isinstance(p["member"], int) else None, pic=p["pic"] if isinstance(p["pic"], int) else None, port=p["port"] if isinstance(p["port"], int) else None))
        state.admin_status, state.oper_status = match.group("admin"), match.group("link")
    return present

def parse_lldp_neighbors_text(text: str, observed_at: str, raw_artifact: str) -> list[dict]:
    result=[]
    for block in text.split("LLDP Neighbor Information:")[1:]:
        local=_find(block,r"Local Interface\s*:\s*(\S+)")
        system=_find(block,r"System name\s*:\s*([^\n]+)")
        port=_find(block,r"Port ID\s*:\s*(\S+)")
        parent=_find(block,r"Parent Interface\s*:\s*(\S+)")
        if local and system:
            result.append({"observed_at":observed_at,"local_interface":local,"parent_interface":None if parent=="-" else parent,"remote_system_name":system,"remote_port_id":port,"raw_artifact":raw_artifact})
    return result


def _find(text: str, pattern: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1).strip() if match else None
