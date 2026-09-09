from __future__ import annotations

import re

from ex_migration_discovery.parsers import parse_mac_table_text

from .core import ProvisioningError
from .port_state import classify_port_state, parse_terse_states


_EDGE = re.compile(r"^ge-(?P<member>\d+)/0/(?P<port>\d+)$")
_TRUNK_MODE = re.compile(
    r"(?m)^set interfaces (?P<if>\S+) unit 0 family ethernet-switching interface-mode trunk\s*$"
)
_TRUNK_MEMBER = re.compile(
    r"(?m)^set interfaces (?P<if>\S+) unit 0 family ethernet-switching vlan members (?P<value>\S+)\s*$"
)


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def edge_interfaces(member_ids, uplink_interfaces=None):
    excluded = {str(value) for value in (uplink_interfaces or [])}
    values = []
    for member in sorted(set(int(value) for value in member_ids)):
        for port in range(48):
            name = "ge-%d/0/%d" % (member, port)
            if name not in excluded:
                values.append(name)
    return values


def current_port_states(terse_text, mac_table_text, interfaces, observed_at=None):
    terse = parse_terse_states(terse_text)
    dynamic = set()
    for row in parse_mac_table_text(
        mac_table_text or "",
        observed_at,
        "final-access-hardening",
    ):
        if row.mac_type == "dynamic" and row.physical_interface:
            dynamic.add(str(row.physical_interface))
    result = {}
    for interface in interfaces:
        state = terse.get(interface)
        if state is None:
            result[interface] = {
                "interface": interface,
                "admin_status": None,
                "oper_status": None,
                "dynamic_mac_present": interface in dynamic,
                "state": "NOT_OBSERVED",
            }
            continue
        result[interface] = {
            "interface": interface,
            "admin_status": state["admin_status"],
            "oper_status": state["oper_status"],
            "dynamic_mac_present": interface in dynamic,
            "state": classify_port_state(
                state["admin_status"],
                state["oper_status"],
                interface in dynamic,
            ),
        }
    return result


def classify_final_ports(plan, live_completed_by_old, current_states, recovery_interface):
    completed_by_new = {
        str(row.get("new_interface")): str(old)
        for old, row in live_completed_by_old.items()
        if row.get("new_interface")
    }
    intents = {
        str(item.get("old_interface")): item
        for item in plan.get("port_intents", [])
        if item.get("old_interface")
    }
    rows = []
    blockers = []

    for interface in sorted(current_states):
        observed = current_states[interface]
        completed_old = completed_by_new.get(interface)
        same_position_intent = intents.get(interface)

        if completed_old:
            disposition = "USED_KEEP_ENABLED"
            reason = "CONFIRMED_ENDPOINT_MAPPING"
        elif same_position_intent and same_position_intent.get("planned_action") == "CORRELATE_AFTER_CABLE_MOVE":
            disposition = "BLOCKED"
            reason = "APPROVED_ENDPOINT_INTENT_NOT_COMPLETED"
        elif same_position_intent and same_position_intent.get("planned_action") == "HOLD_FOR_OPERATOR_RESOLUTION":
            disposition = "BLOCKED"
            reason = "APPROVED_ENDPOINT_INTENT_REQUIRES_OPERATOR_RESOLUTION"
        elif observed["state"] in ("ACTIVE_MAC", "UP_SILENT"):
            disposition = "BLOCKED"
            reason = "UNMAPPED_PORT_CURRENTLY_ACTIVE" if observed["state"] == "ACTIVE_MAC" else "UNMAPPED_PORT_UP_SILENT"
        elif observed["state"] == "NOT_OBSERVED" and interface != recovery_interface:
            disposition = "BLOCKED"
            reason = "CONFIGURED_EDGE_PORT_NOT_OBSERVED"
        else:
            disposition = "UNUSED_DISABLE"
            if interface == recovery_interface:
                reason = "RECOVERY_PORT_RETIRED_AT_CLEANUP"
            elif same_position_intent and same_position_intent.get("planned_action") == "LEAVE_TEMPLATE_DEFAULT":
                reason = "APPROVED_UNUSED_PORT_INTENT"
            else:
                reason = "NO_APPROVED_ENDPOINT_INTENT_AND_NO_CURRENT_ACTIVITY"

        row = {
            "interface": interface,
            "state": observed["state"],
            "admin_status": observed["admin_status"],
            "oper_status": observed["oper_status"],
            "dynamic_mac_present": observed["dynamic_mac_present"],
            "completed_old_interface": completed_old,
            "planned_action": same_position_intent.get("planned_action") if same_position_intent else None,
            "disposition": disposition,
            "reason": reason,
        }
        rows.append(row)
        if disposition == "BLOCKED":
            blockers.append(row)

    return {
        "rows": rows,
        "used": [row for row in rows if row["disposition"] == "USED_KEEP_ENABLED"],
        "unused": [row for row in rows if row["disposition"] == "UNUSED_DISABLE"],
        "blockers": blockers,
        "result": "PASS" if not blockers else "FAIL",
    }


def trunk_inventory(config_text):
    trunks = sorted(set(match.group("if") for match in _TRUNK_MODE.finditer(str(config_text or ""))))
    memberships = {}
    for interface in trunks:
        memberships[interface] = sorted(set(
            match.group("value")
            for match in _TRUNK_MEMBER.finditer(str(config_text or ""))
            if match.group("if") == interface
        ))
    return {"trunks": trunks, "memberships": memberships}


def hardening_statements(
    unused_interfaces,
    used_interfaces,
    production_vlan_names,
    uplink_interface="ae0",
    inactive_vlan_name="default",
):
    _require(production_vlan_names, "at least one approved production VLAN is required")
    statements = [
        "delete interfaces %s unit 0 family ethernet-switching vlan members all" % uplink_interface,
    ]
    for name in sorted(set(str(value) for value in production_vlan_names)):
        _require(name not in ("default", "TEMP-RECOVERY"), "inactive/recovery VLAN cannot be an uplink production member")
        statements.append(
            "set interfaces %s unit 0 family ethernet-switching vlan members %s"
            % (uplink_interface, name)
        )
    for interface in sorted(set(unused_interfaces)):
        statements.extend([
            "set interfaces %s disable" % interface,
            "set interfaces %s unit 0 family ethernet-switching vlan members %s"
            % (interface, inactive_vlan_name),
        ])
    # The pre-stage voice policy is intentionally broad. At finalization it is
    # narrowed to ports that are actually carrying confirmed endpoint intent.
    statements.append("delete switch-options voip interface edge_ports")
    for interface in sorted(set(used_interfaces)):
        statements.append("set switch-options voip interface %s vlan voip" % interface)
    return statements


def validate_final_hardening(
    config_text,
    port_states,
    used_interfaces,
    unused_interfaces,
    production_vlan_names,
    uplink_interface="ae0",
    inactive_vlan_name="default",
):
    lines = {line.strip() for line in str(config_text or "").splitlines() if line.strip()}
    trunks = trunk_inventory(config_text)
    checks = {
        "only_expected_access_uplink_trunk": trunks["trunks"] == [uplink_interface],
        "uplink_all_membership_absent": (
            "set interfaces %s unit 0 family ethernet-switching vlan members all" % uplink_interface
        ) not in lines,
        "all_approved_production_vlans_on_uplink": all(
            "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (uplink_interface, name) in lines
            for name in production_vlan_names
        ),
        "inactive_vlan_not_on_uplink": (
            "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (uplink_interface, inactive_vlan_name)
        ) not in lines,
        "broad_voice_policy_removed": "set switch-options voip interface edge_ports vlan voip" not in lines,
        "voice_policy_on_used_ports": all(
            "set switch-options voip interface %s vlan voip" % interface in lines
            for interface in used_interfaces
        ),
    }
    for interface in sorted(set(unused_interfaces)):
        checks["%s_disabled" % interface] = "set interfaces %s disable" % interface in lines
        checks["%s_in_inactive_vlan" % interface] = (
            "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (interface, inactive_vlan_name)
        ) in lines
    for interface in sorted(set(used_interfaces)):
        checks["%s_not_disabled" % interface] = "set interfaces %s disable" % interface not in lines
    return {
        "checks": checks,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "port_states": port_states,
    }
