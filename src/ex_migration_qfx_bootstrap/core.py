from __future__ import annotations

import json
from pathlib import Path


class BootstrapConfigError(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise BootstrapConfigError(message)


def validate_config(config):
    _require(isinstance(config, dict), "bootstrap config must be a JSON object")

    pair = config.get("qfx_pair")
    _require(isinstance(pair, list) and len(pair) == 2, "qfx_pair must contain exactly two devices")
    roles = [item.get("role") for item in pair if isinstance(item, dict)]
    _require(sorted(roles) == ["qfx-a", "qfx-b"], "qfx_pair roles must be qfx-a and qfx-b")
    for item in pair:
        _require(item.get("management_address"), "each QFX requires management_address")

    vlan = config.get("management_vlan") or {}
    _require(vlan.get("name"), "management_vlan.name is required")
    try:
        vlan_id = int(vlan.get("vlan_id"))
    except (TypeError, ValueError):
        raise BootstrapConfigError("management_vlan.vlan_id must be an integer")
    _require(1 <= vlan_id <= 4094, "management_vlan.vlan_id must be between 1 and 4094")

    interfaces = config.get("interfaces") or {}
    _require(interfaces.get("type") == "et", "interfaces.type must be et")
    for key in ("pic", "first_port", "last_port", "ports_per_fpc"):
        try:
            interfaces[key] = int(interfaces[key])
        except (KeyError, TypeError, ValueError):
            raise BootstrapConfigError("interfaces.%s must be an integer" % key)
    _require(interfaces["pic"] >= 0, "interfaces.pic must be non-negative")
    _require(interfaces["first_port"] >= 0, "interfaces.first_port must be non-negative")
    _require(
        interfaces["first_port"] <= interfaces["last_port"],
        "interfaces.first_port must not exceed interfaces.last_port",
    )
    _require(interfaces["ports_per_fpc"] > 0, "interfaces.ports_per_fpc must be positive")
    _require(
        interfaces["last_port"] < interfaces["ports_per_fpc"],
        "interfaces.last_port must be less than interfaces.ports_per_fpc",
    )

    prefix = (config.get("lacp_system_id") or {}).get("prefix", "02:00:00:00")
    octets = prefix.split(":")
    _require(len(octets) == 4, "lacp_system_id.prefix must contain four octets")
    try:
        values = [int(value, 16) for value in octets]
    except ValueError:
        raise BootstrapConfigError("lacp_system_id.prefix contains a non-hex octet")
    _require(all(0 <= value <= 255 for value in values), "lacp_system_id.prefix contains an invalid octet")
    config.setdefault("lacp_system_id", {})["prefix"] = ":".join("%02x" % value for value in values)
    return config


def load_config(path):
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        return validate_config(json.load(handle))


def ae_number(fpc, port, ports_per_fpc=16):
    fpc = int(fpc)
    port = int(port)
    ports_per_fpc = int(ports_per_fpc)
    _require(fpc >= 0, "FPC must be non-negative")
    _require(ports_per_fpc > 0, "ports_per_fpc must be positive")
    _require(0 <= port < ports_per_fpc, "port is outside the AE numbering namespace")
    return (fpc * ports_per_fpc) + port


def candidate_interfaces(fpcs, config):
    interfaces = config["interfaces"]
    result = []
    for fpc in sorted({int(value) for value in fpcs}):
        _require(fpc >= 0, "FPC must be non-negative")
        for port in range(interfaces["first_port"], interfaces["last_port"] + 1):
            number = ae_number(fpc, port, interfaces["ports_per_fpc"])
            result.append({
                "fpc": fpc,
                "pic": interfaces["pic"],
                "port": port,
                "physical_interface": "%s-%d/%d/%d" % (
                    interfaces["type"], fpc, interfaces["pic"], port
                ),
                "ae_interface": "ae%d" % number,
                "ae_number": number,
            })
    return result


def lacp_system_id(number, prefix="02:00:00:00"):
    number = int(number)
    _require(0 <= number <= 65535, "AE number cannot be represented in deterministic LACP system ID")
    return "%s:%02x:%02x" % (prefix.lower(), (number >> 8) & 0xff, number & 0xff)


def render_esi_lag(candidate, config):
    ae = candidate["ae_interface"]
    physical = candidate["physical_interface"]
    system_id = lacp_system_id(candidate["ae_number"], config["lacp_system_id"]["prefix"])
    vlan_name = config["management_vlan"]["name"]
    return [
        "set interfaces %s esi auto-derive type-1-lacp" % ae,
        "set interfaces %s esi all-active" % ae,
        "set interfaces %s aggregated-ether-options lacp active" % ae,
        "set interfaces %s aggregated-ether-options lacp system-id %s" % (ae, system_id),
        "set interfaces %s unit 0 family ethernet-switching interface-mode trunk" % ae,
        "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (ae, vlan_name),
        "set interfaces %s ether-options 802.3ad %s" % (physical, ae),
    ]
