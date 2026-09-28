from __future__ import annotations

import re

from .core import candidate_interfaces, render_esi_lag


_FPC_LINE = re.compile(r"^\s*(?P<fpc>\d+)\s+(?P<state>Online|Offline|Empty|Present|Testing|Onlining)\b", re.I)
_VLAN_LINE = re.compile(r"(?m)^set vlans (?P<name>\S+) vlan-id (?P<id>\d+)\s*$")


def discover_online_fpcs(dev):
    """Return online FPC slot numbers without depending on optic presence."""
    text = dev.cli("show chassis fpc", warning=False) or ""
    result = []
    for line in text.splitlines():
        match = _FPC_LINE.match(line)
        if match and match.group("state").lower() == "online":
            result.append(int(match.group("fpc")))
    return sorted(set(result))


def _interface_config(dev, interface):
    text = dev.cli(
        "show configuration interfaces %s | display set" % interface,
        warning=False,
    ) or ""
    return text.strip()


def _vlan_config(dev):
    return dev.cli("show configuration vlans | display set", warning=False) or ""


def verify_management_vlan(dev, config):
    expected_name = config["management_vlan"]["name"]
    expected_id = int(config["management_vlan"]["vlan_id"])
    definitions = [
        (match.group("name"), int(match.group("id")))
        for match in _VLAN_LINE.finditer(_vlan_config(dev))
    ]
    by_name = [item for item in definitions if item[0] == expected_name]
    by_id = [item for item in definitions if item[1] == expected_id]
    ok = by_name == [(expected_name, expected_id)] and by_id == [(expected_name, expected_id)]
    return {
        "name": expected_name,
        "vlan_id": expected_id,
        "definitions_by_name": by_name,
        "definitions_by_id": by_id,
        "result": "PASS" if ok else "FAIL",
    }


def observe_candidate(dev, candidate, config):
    physical = candidate["physical_interface"]
    ae = candidate["ae_interface"]
    physical_config = _interface_config(dev, physical)
    ae_config = _interface_config(dev, ae)
    expected = render_esi_lag(candidate, config)

    if physical_config:
        state = "SKIP_PHYSICAL_CONFIGURED"
    elif ae_config:
        state = "SKIP_AE_CONFIGURED"
    else:
        state = "AVAILABLE"

    return {
        **candidate,
        "state": state,
        "physical_config": physical_config,
        "ae_config": ae_config,
        "candidate_statements": expected,
    }


def build_pair_preflight(devices, config):
    """Build a read-only pair plan. Nothing in this function changes Junos config."""
    fpcs = {role: discover_online_fpcs(dev) for role, dev in devices.items()}
    common_fpcs = sorted(set(fpcs.get("qfx-a", [])) & set(fpcs.get("qfx-b", [])))
    vlan = {
        role: verify_management_vlan(dev, config)
        for role, dev in devices.items()
    }

    rows = []
    for candidate in candidate_interfaces(common_fpcs, config):
        observed = {
            role: observe_candidate(dev, candidate, config)
            for role, dev in devices.items()
        }
        states = {role: value["state"] for role, value in observed.items()}
        if all(value == "AVAILABLE" for value in states.values()):
            pair_state = "CREATE"
        elif all(value != "AVAILABLE" for value in states.values()):
            pair_state = "SKIP_CONFIGURED"
        else:
            pair_state = "WARN_ASYMMETRIC"
        rows.append({
            **candidate,
            "pair_state": pair_state,
            "devices": observed,
        })

    fpc_symmetry = fpcs.get("qfx-a", []) == fpcs.get("qfx-b", [])
    vlan_ok = all(item["result"] == "PASS" for item in vlan.values())
    asymmetric = [row for row in rows if row["pair_state"] == "WARN_ASYMMETRIC"]
    creates = [row for row in rows if row["pair_state"] == "CREATE"]
    return {
        "fpcs": fpcs,
        "common_fpcs": common_fpcs,
        "checks": {
            "matching_online_fpcs": fpc_symmetry,
            "management_vlan_matches": vlan_ok,
            "no_asymmetric_port_ownership": not asymmetric,
        },
        "management_vlan": vlan,
        "candidates": rows,
        "create_count": len(creates),
        "skip_count": len([row for row in rows if row["pair_state"] == "SKIP_CONFIGURED"]),
        "warning_count": len(asymmetric),
        "result": "PASS" if fpc_symmetry and vlan_ok and not asymmetric else "FAIL",
        "safety": {
            "read_only": True,
            "device_writes_authorized": False,
            "optic_presence_required": False,
        },
    }
