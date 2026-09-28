from __future__ import annotations

import re
from collections import defaultdict

from ex_migration_analyzer.core import utc_now
from ex_migration_discovery.normalize import normalize_mac

from .core import ProvisioningError
from .postcutover_observation import build_postcutover_observation


_EDGE = re.compile(r"^ge-(?P<member>\d+)/0/(?P<port>\d+)$")
_PHYSICAL = re.compile(r"^(?:ge|xe|et)-\d+/\d+/\d+$")


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def _member_ids(identity):
    members = (
        identity.get("observed", {})
        .get("device", {})
        .get("members", [])
    )
    values = sorted({int(item["member_id"]) for item in members})
    _require(values, "approved EX4400 identity has no VC member inventory")
    return values


def _package_variables(package):
    values = package.get("variables") or {}
    _require(isinstance(values, dict), "pre-stage package variables are invalid")
    return values


def _eligible_destination_ports(identity, package):
    variables = _package_variables(package)
    excluded = {str(value) for value in (variables.get("uplink_interfaces") or [])}
    recovery = str(variables.get("recovery_interface") or "")
    if recovery:
        excluded.add(recovery)

    ports = []
    for member in _member_ids(identity):
        for port in range(48):
            name = "ge-%d/0/%d" % (member, port)
            if name not in excluded:
                ports.append(name)
    _require(ports, "approved EX4400 identity/package expose no eligible client ports")
    return ports


def _endpoint_intents(plan):
    values = []
    mac_owner = {}
    for intent in sorted(
        plan.get("port_intents", []),
        key=lambda item: str(item.get("old_interface") or ""),
    ):
        if intent.get("planned_action") != "CORRELATE_AFTER_CABLE_MOVE":
            continue
        old_interface = str(intent.get("old_interface") or "")
        _require(old_interface, "approved endpoint intent has no old interface")
        macs = []
        for value in intent.get("endpoint_macs") or []:
            try:
                mac = normalize_mac(str(value))
            except ValueError as exc:
                raise ProvisioningError(
                    "approved endpoint intent %s contains invalid MAC %r: %s"
                    % (old_interface, value, exc)
                )
            previous = mac_owner.get(mac)
            _require(
                previous in (None, old_interface),
                "approved endpoint MAC %s belongs to multiple correlatable old interfaces"
                % mac,
            )
            mac_owner[mac] = old_interface
            macs.append(mac)
        macs = sorted(set(macs))
        if not macs:
            continue
        row = dict(intent)
        row["old_interface"] = old_interface
        row["endpoint_macs"] = macs
        values.append(row)
    _require(values, "approved plan has no correlatable endpoint intents with MAC evidence")
    return values


def _initial_placements(plan, identity, package):
    intents = _endpoint_intents(plan)
    eligible = _eligible_destination_ports(identity, package)
    available = set(eligible)
    placements = []

    for intent in intents:
        old_interface = intent["old_interface"]
        if old_interface in available:
            new_interface = old_interface
        else:
            _require(
                available,
                "EX4400 client-port inventory is too small for all approved endpoint intents",
            )
            new_interface = sorted(available)[0]
        available.remove(new_interface)
        placements.append({
            "old_interface": old_interface,
            "new_interface": new_interface,
            "endpoint_macs": list(intent["endpoint_macs"]),
            "intent": intent,
        })
    return placements


def _interface_member(interface):
    match = _EDGE.fullmatch(str(interface or ""))
    return int(match.group("member")) if match else None


def _select_swap_pairs(placements, swap_pairs):
    count = int(swap_pairs)
    _require(count >= 0, "--swap-pairs cannot be negative")
    if count == 0:
        return []

    by_member = defaultdict(list)
    for row in placements:
        member = _interface_member(row["new_interface"])
        if member is not None:
            by_member[member].append(row)

    pairs = []
    used = set()

    # Prefer one swap pair per VC member so a multi-member test exercises more
    # than one member before taking a second pair from the same member.
    for member in sorted(by_member):
        candidates = [
            row for row in sorted(
                by_member[member], key=lambda item: item["old_interface"]
            )
            if row["old_interface"] not in used
        ]
        if len(candidates) < 2:
            continue
        a, b = candidates[0], candidates[1]
        pairs.append((a, b))
        used.update((a["old_interface"], b["old_interface"]))
        if len(pairs) == count:
            return pairs

    remaining = [
        row for row in sorted(placements, key=lambda item: item["old_interface"])
        if row["old_interface"] not in used
    ]
    while len(pairs) < count and len(remaining) >= 2:
        a = remaining.pop(0)
        b = remaining.pop(0)
        pairs.append((a, b))
        used.update((a["old_interface"], b["old_interface"]))

    _require(
        len(pairs) == count,
        "requested %d swap pair(s), but only %d populated endpoint port(s) are available"
        % (count, len(placements)),
    )
    return pairs


def _apply_swaps(placements, swap_pairs):
    pairs = _select_swap_pairs(placements, swap_pairs)
    by_old = {row["old_interface"]: row for row in placements}
    mutations = []
    for a, b in pairs:
        a_dest = a["new_interface"]
        b_dest = b["new_interface"]
        by_old[a["old_interface"]]["new_interface"] = b_dest
        by_old[b["old_interface"]]["new_interface"] = a_dest
        mutations.append({
            "a": {
                "old_interface": a["old_interface"],
                "new_interface": b_dest,
            },
            "b": {
                "old_interface": b["old_interface"],
                "new_interface": a_dest,
            },
        })
    return [by_old[key] for key in sorted(by_old)], mutations


def _vlan_name(plan, vlan_id):
    for item in plan.get("vlan_intents", []):
        if item.get("vlan_id") is not None and int(item["vlan_id"]) == int(vlan_id):
            name = str(item.get("name") or "")
            if name:
                return name
    return None


def _historical_vlan_ids(intent, mac):
    values = set()
    for item in intent.get("historical_observations") or []:
        try:
            observed_mac = normalize_mac(str(item.get("mac") or ""))
        except ValueError:
            continue
        if observed_mac != mac:
            continue
        vlan_id = item.get("vlan_id")
        if vlan_id is None and isinstance(item.get("vlan"), dict):
            vlan_id = item["vlan"].get("vlan_id")
        if vlan_id is not None:
            values.add(int(vlan_id))
    return values


def _mac_vlan(intent, mac, plan, package):
    variables = _package_variables(package)
    voice_id = variables.get("voice_vlan_id")
    prestage_id = variables.get("prestage_access_vlan_id")
    _require(voice_id is not None, "pre-stage package has no voice VLAN ID")
    _require(prestage_id is not None, "pre-stage package has no holding VLAN ID")
    voice_id = int(voice_id)
    prestage_id = int(prestage_id)
    voice_name = str(
        variables.get("voice_vlan_name")
        or (variables.get("voice_vlan") or {}).get("name")
        or _vlan_name(plan, voice_id)
        or "voip"
    )
    prestage_name = str(
        variables.get("prestage_access_vlan_name")
        or (variables.get("prestage_access_vlan") or {}).get("name")
        or "default"
    )

    explicit_voice = set()
    for value in intent.get("voice_macs") or []:
        try:
            explicit_voice.add(normalize_mac(str(value)))
        except ValueError:
            continue
    historical_ids = _historical_vlan_ids(intent, mac)
    if mac in explicit_voice or voice_id in historical_ids:
        return voice_name, voice_id
    return prestage_name, prestage_id


def _render_mac_table(placements, plan, package):
    blocks = []
    for placement in placements:
        interface = placement["new_interface"]
        intent = placement["intent"]
        for mac in placement["endpoint_macs"]:
            vlan_name, vlan_id = _mac_vlan(intent, mac, plan, package)
            blocks.extend([
                "MAC address: %s" % mac,
                "Routing instance: default-switch",
                "VLAN name: %s, VLAN ID: %s" % (vlan_name, vlan_id),
                "Learning interface: %s.0" % interface,
                "Layer 2 flags: 0x1",
                "",
            ])
    return "\n".join(blocks)


def _prestate_status(intent):
    state = (intent.get("pre_migration_state") or {}).get("latest_state")
    if state == "ADMIN_DOWN":
        return "down", "down"
    if state == "UP_SILENT":
        return "up", "up"
    if state == "LINK_DOWN":
        return "up", "down"
    if state == "ACTIVE_MAC":
        return "up", "up"
    return "up", "down"


def _render_terse(placements, plan, identity, package):
    status = {}
    intents_by_old = {
        str(item.get("old_interface") or ""): item
        for item in plan.get("port_intents", [])
        if item.get("old_interface")
    }

    for member in _member_ids(identity):
        for port in range(48):
            interface = "ge-%d/0/%d" % (member, port)
            status[interface] = _prestate_status(intents_by_old.get(interface, {}))

    for interface in _package_variables(package).get("uplink_interfaces") or []:
        interface = str(interface)
        if _PHYSICAL.fullmatch(interface):
            status[interface] = ("up", "up")

    for placement in placements:
        status[placement["new_interface"]] = ("up", "up")

    return "\n".join(
        "%-24s %-5s %s" % (interface, admin, oper)
        for interface, (admin, oper) in sorted(status.items())
    ) + "\n"


def _synthetic_current_identity(plan, identity):
    observed = identity.get("observed") or {}
    device = dict(observed.get("device") or {})
    device["members"] = [
        dict(item) for item in (device.get("members") or [])
    ]
    target_hostname = str(
        plan.get("template_variables", {}).get("new_hostname")
        or device.get("hostname")
        or ""
    )
    device["hostname"] = target_hostname
    return {
        "connection": dict(observed.get("connection") or {}),
        "device": device,
    }


def _scenario_name(swap_pairs):
    count = int(swap_pairs)
    if count == 0:
        return "NORMAL_NO_SWAPS"
    if count == 2:
        return "NORMAL_WITH_TWO_SWAPS"
    return "NORMAL_WITH_%d_SWAP_PAIRS" % count


def build_simulated_postcutover_observation(
    migration_id,
    approved_plan,
    approved_plan_digest,
    identity,
    identity_digest,
    package,
    package_digest,
    access,
    swap_pairs=2,
    observed_at=None,
):
    placements = _initial_placements(approved_plan, identity, package)
    placements, mutations = _apply_swaps(placements, swap_pairs)
    mac_text = _render_mac_table(placements, approved_plan, package)
    terse_text = _render_terse(placements, approved_plan, identity, package)
    stamp = observed_at or utc_now()

    observation = build_postcutover_observation(
        migration_id,
        approved_plan,
        approved_plan_digest,
        identity,
        identity_digest,
        package,
        package_digest,
        access,
        _synthetic_current_identity(approved_plan, identity),
        mac_text,
        terse_text,
        source_kind="SIMULATED",
        started_at=stamp,
        completed_at=stamp,
    )

    moved = [
        row for row in placements
        if row["old_interface"] != row["new_interface"]
    ]
    unchanged = [
        row for row in placements
        if row["old_interface"] == row["new_interface"]
    ]
    scenario = {
        "name": _scenario_name(swap_pairs),
        "swap_pairs": int(swap_pairs),
        "mutations": mutations,
        "placements": [
            {
                "old_interface": row["old_interface"],
                "new_interface": row["new_interface"],
                "endpoint_macs": list(row["endpoint_macs"]),
                "moved": row["old_interface"] != row["new_interface"],
            }
            for row in placements
        ],
        "statistics": {
            "correlatable_endpoint_intents": len(placements),
            "approved_endpoint_macs": len({
                mac for row in placements for mac in row["endpoint_macs"]
            }),
            "same_position_placements": len(unchanged),
            "moved_placements": len(moved),
            "missing_endpoints": 0,
            "unexpected_endpoints": 0,
        },
    }
    return {
        "observation": observation,
        "mac_table_text": mac_text,
        "terse_text": terse_text,
        "scenario": scenario,
    }
