from __future__ import annotations

import re

from ex_migration_discovery.parsers import parse_mac_table_text

from .core import ProvisioningError
from .port_state import classify_port_state, parse_terse_states


_TRUNK_MODE = re.compile(
    r"(?m)^set interfaces (?P<if>\S+) unit 0 family ethernet-switching interface-mode trunk\s*$"
)
_TRUNK_MEMBER = re.compile(
    r"(?m)^set interfaces (?P<if>\S+) unit 0 family ethernet-switching vlan members (?P<value>\S+)\s*$"
)
_ACCESS_MEMBER = re.compile(
    r"(?m)^set interfaces (?P<if>ge-\d+/0/\d+) unit 0 family ethernet-switching vlan members (?P<value>\S+)\s*$"
)
_VOICE = re.compile(
    r"(?m)^set switch-options voip interface (?P<if>\S+) vlan (?P<vlan>\S+)\s*$"
)
_EDGE_RANGE = re.compile(
    r'(?m)^set interfaces interface-range edge_ports member "(?P<member>[^"]+)"\s*$'
)


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def _expand_numeric_component(value):
    text = str(value)
    if text.isdigit():
        return [int(text)]
    match = re.fullmatch(r"\[(\d+)-(\d+)\]", text)
    _require(match is not None, "unsupported Junos interface-range numeric component %r" % text)
    low, high = int(match.group(1)), int(match.group(2))
    _require(low <= high, "invalid descending Junos interface-range component %r" % text)
    return list(range(low, high + 1))


def edge_range_expression(config_text):
    values = [match.group("member") for match in _EDGE_RANGE.finditer(str(config_text or ""))]
    _require(len(values) == 1, "live EX configuration must contain exactly one quoted edge_ports member expression")
    return values[0]


def expand_edge_range(expression, member_ids=None):
    match = re.fullmatch(
        r"(?P<media>[a-z]+)-(?P<member>\d+|\[\d+-\d+\])/"
        r"(?P<pic>\d+|\[\d+-\d+\])/(?P<port>\d+|\[\d+-\d+\])",
        str(expression),
    )
    _require(match is not None, "unsupported edge_ports Junos interface-range expression %r" % expression)
    _require(match.group("media") == "ge", "cleanup currently supports GE edge_ports expressions only")
    members = _expand_numeric_component(match.group("member"))
    pics = _expand_numeric_component(match.group("pic"))
    ports = _expand_numeric_component(match.group("port"))
    if member_ids is not None:
        approved_members = {int(value) for value in member_ids}
        members = [value for value in members if value in approved_members]
        _require(members, "edge_ports expression has no interfaces on the approved VC members")
    return [
        "%s-%d/%d/%d" % (match.group("media"), member, pic, port)
        for member in members
        for pic in pics
        for port in ports
    ]


def edge_interfaces(config_text, member_ids, uplink_interfaces=None):
    expression = edge_range_expression(config_text)
    values = expand_edge_range(expression, member_ids)
    excluded = {str(value) for value in (uplink_interfaces or [])}
    overlap = sorted(set(values) & excluded)
    _require(
        not overlap,
        "template-owned edge_ports range overlaps approved AE uplink interface(s): %s"
        % ", ".join(overlap),
    )
    return values


def final_production_vlan_names(configured_vlans, management_vlan_id, required_qfx_vlan_ids):
    by_id = {}
    for item in configured_vlans or []:
        vlan_id = item.get("vlan_id")
        name = str(item.get("name") or "")
        if vlan_id is None or not name:
            continue
        vlan_id = int(vlan_id)
        _require(vlan_id not in by_id, "configured VLAN inventory contains duplicate VLAN ID %s" % vlan_id)
        by_id[vlan_id] = name
    required = {int(value) for value in (required_qfx_vlan_ids or [])}
    required.add(int(management_vlan_id))
    missing = sorted(required - set(by_id))
    _require(
        not missing,
        "current QFX-plan VLAN lineage cannot be resolved in the approved EX VLAN inventory: %s"
        % ", ".join(str(value) for value in missing),
    )
    return [by_id[vlan_id] for vlan_id in sorted(required)]


def stale_vlan_cleanup(config_text, mac_table_text, configured_vlans, keep_vlan_ids, observed_at=None):
    lines = [line.strip() for line in str(config_text or "").splitlines() if line.strip()]
    dynamic_ids = set()
    for row in parse_mac_table_text(
        mac_table_text or "",
        observed_at,
        "final-access-hardening-vlan-prune",
    ):
        if row.mac_type == "dynamic" and getattr(row, "vlan", None) is not None:
            vlan_id = getattr(row.vlan, "vlan_id", None)
            if vlan_id is not None:
                dynamic_ids.add(int(vlan_id))

    keep = {int(value) for value in (keep_vlan_ids or [])}
    delete = []
    preserve = []
    for item in sorted(
        (dict(value) for value in (configured_vlans or []) if value.get("vlan_id") is not None),
        key=lambda value: int(value["vlan_id"]),
    ):
        name = str(item.get("name") or "")
        vlan_id = int(item["vlan_id"])
        classification = str(item.get("classification") or "")
        if vlan_id in keep:
            continue
        if classification != "data":
            preserve.append({
                "name": name,
                "vlan_id": vlan_id,
                "reason": "NON_DATA_VLAN",
                "references": [],
            })
            continue

        own_prefix = "set vlans %s " % name
        external = sorted(
            line for line in lines
            if not line.startswith(own_prefix)
            and (
                re.search(r"(^|\s)%s(?:\s|$)" % re.escape(name), line)
                or re.search(
                    r"family ethernet-switching vlan members %s(?:\s|$)" % vlan_id,
                    line,
                )
            )
        )
        l3 = sorted(
            line for line in lines
            if line.startswith(own_prefix + "l3-interface ")
        )
        reasons = []
        if external:
            reasons.append("EXTERNAL_CONFIGURATION_REFERENCE")
        if l3:
            reasons.append("L3_INTERFACE_PRESENT")
        if vlan_id in dynamic_ids:
            reasons.append("DYNAMIC_MAC_PRESENT")
        if reasons:
            preserve.append({
                "name": name,
                "vlan_id": vlan_id,
                "reason": "+".join(reasons),
                "references": external + l3,
            })
        else:
            delete.append({
                "name": name,
                "vlan_id": vlan_id,
                "reason": "PROVEN_UNUSED_DATA_VLAN",
                "references": [],
            })
    return {"delete": delete, "preserve": preserve}


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

        if completed_old and observed["admin_status"] == "down":
            disposition = "BLOCKED"
            reason = "CONFIRMED_ENDPOINT_PORT_ADMIN_DOWN"
        elif completed_old:
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
            if interface == recovery_interface:
                reason = (
                    "RECOVERY_PORT_CURRENTLY_ACTIVE"
                    if observed["state"] == "ACTIVE_MAC"
                    else "RECOVERY_PORT_UP_SILENT"
                )
            else:
                reason = (
                    "UNMAPPED_PORT_CURRENTLY_ACTIVE"
                    if observed["state"] == "ACTIVE_MAC"
                    else "UNMAPPED_PORT_UP_SILENT"
                )
        elif observed["state"] == "NOT_OBSERVED":
            disposition = "BLOCKED"
            reason = "CONFIGURED_EDGE_PORT_NOT_OBSERVED"
        elif interface == recovery_interface:
            disposition = "UNUSED_DISABLE"
            reason = "RECOVERY_PORT_PROVEN_INACTIVE_AT_CLEANUP"
        else:
            disposition = "UNUSED_DISABLE"
            if same_position_intent and same_position_intent.get("planned_action") == "LEAVE_TEMPLATE_DEFAULT":
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


def explicit_access_memberships(config_text):
    values = {}
    for match in _ACCESS_MEMBER.finditer(str(config_text or "")):
        values.setdefault(match.group("if"), set()).add(match.group("value"))
    return {interface: sorted(items) for interface, items in values.items()}


def voice_inventory(config_text):
    rows = []
    for match in _VOICE.finditer(str(config_text or "")):
        rows.append({"interface": match.group("if"), "vlan": match.group("vlan")})
    return sorted(rows, key=lambda item: (item["interface"], item["vlan"]))


def validate_pre_hardening_config(
    config_text,
    classification,
    recovery_interface,
    recovery_vlan_name,
    voice_vlan_name,
    uplink_interface="ae0",
    inactive_vlan_name="default",
):
    trunks = trunk_inventory(config_text)
    memberships = explicit_access_memberships(config_text)
    voice = voice_inventory(config_text)
    edge_expression = edge_range_expression(config_text)
    checks = {
        "only_expected_access_uplink_trunk": trunks["trunks"] == [uplink_interface],
        "uplink_membership_exactly_all": trunks["memberships"].get(uplink_interface) == ["all"],
        "voice_policy_exactly_broad_edge_range": voice == [{"interface": "edge_ports", "vlan": voice_vlan_name}],
        "template_owned_edge_range_present": bool(edge_expression),
    }
    unexpected = []
    for row in classification.get("unused", []):
        interface = row["interface"]
        allowed = {inactive_vlan_name}
        if interface == recovery_interface:
            allowed.add(recovery_vlan_name)
        current = set(memberships.get(interface, []))
        extras = sorted(current - allowed)
        if extras:
            unexpected.append({
                "interface": interface,
                "memberships": sorted(current),
                "unexpected": extras,
            })
    checks["unused_ports_have_no_unexpected_explicit_vlan_membership"] = not unexpected
    return {
        "checks": checks,
        "edge_ports_expression": edge_expression,
        "unexpected_unused_port_memberships": unexpected,
        "result": "PASS" if all(checks.values()) else "FAIL",
    }


def hardening_statements(
    config_text,
    unused_interfaces,
    used_interfaces,
    production_vlan_names,
    voice_vlan_name,
    recovery_vlan_name,
    stale_vlan_names=None,
    uplink_interface="ae0",
    inactive_vlan_name="default",
):
    _require(production_vlan_names, "at least one approved production VLAN is required")
    _require(voice_vlan_name, "voice VLAN name is required")
    lines = {line.strip() for line in str(config_text or "").splitlines() if line.strip()}
    statements = []

    broad = "set switch-options voip interface edge_ports vlan %s" % voice_vlan_name
    _require(broad in lines, "broad edge_ports voice policy is missing before cleanup")

    remove_all = "delete interfaces %s unit 0 family ethernet-switching vlan members all" % uplink_interface
    if "set " + remove_all[len("delete "):] in lines:
        statements.append(remove_all)
    for name in sorted(set(str(value) for value in production_vlan_names)):
        _require(
            name not in (inactive_vlan_name, recovery_vlan_name),
            "inactive/recovery VLAN cannot be an uplink production member",
        )
        statement = (
            "set interfaces %s unit 0 family ethernet-switching vlan members %s"
            % (uplink_interface, name)
        )
        if statement not in lines:
            statements.append(statement)

    for interface in sorted(set(unused_interfaces)):
        disable = "set interfaces %s disable" % interface
        inactive = (
            "set interfaces %s unit 0 family ethernet-switching vlan members %s"
            % (interface, inactive_vlan_name)
        )
        if disable not in lines:
            statements.append(disable)
        if inactive not in lines:
            statements.append(inactive)

    for name in sorted(set(str(value) for value in (stale_vlan_names or []))):
        _require(
            name not in set(production_vlan_names) | {inactive_vlan_name, recovery_vlan_name, voice_vlan_name},
            "protected VLAN cannot be deleted during access hardening",
        )
        owned = sorted(
            (line for line in lines if line.startswith("set vlans %s " % name)),
            key=lambda line: (-len(line.split()), line),
        )
        for line in owned:
            statements.append("delete " + line[len("set "):])
    return statements


def validate_final_hardening(
    config_text,
    port_states,
    used_interfaces,
    unused_interfaces,
    production_vlan_names,
    voice_vlan_name,
    deleted_vlan_names=None,
    expected_edge_expression=None,
    uplink_interface="ae0",
    inactive_vlan_name="default",
):
    lines = {line.strip() for line in str(config_text or "").splitlines() if line.strip()}
    trunks = trunk_inventory(config_text)
    expected_members = sorted(set(str(value) for value in production_vlan_names))
    voice = voice_inventory(config_text)
    current_edge_expression = edge_range_expression(config_text)
    checks = {
        "only_expected_access_uplink_trunk": trunks["trunks"] == [uplink_interface],
        "uplink_all_membership_absent": (
            "set interfaces %s unit 0 family ethernet-switching vlan members all" % uplink_interface
        ) not in lines,
        "uplink_membership_exactly_approved": trunks["memberships"].get(uplink_interface) == expected_members,
        "inactive_vlan_not_on_uplink": (
            "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (uplink_interface, inactive_vlan_name)
        ) not in lines,
        "broad_voice_policy_preserved": voice == [{"interface": "edge_ports", "vlan": voice_vlan_name}],
        "template_owned_edge_range_preserved": (
            expected_edge_expression is None or current_edge_expression == expected_edge_expression
        ),
    }
    for interface in sorted(set(unused_interfaces)):
        checks["%s_disabled" % interface] = "set interfaces %s disable" % interface in lines
        checks["%s_in_inactive_vlan" % interface] = (
            "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (interface, inactive_vlan_name)
        ) in lines
    for interface in sorted(set(used_interfaces)):
        checks["%s_not_disabled" % interface] = "set interfaces %s disable" % interface not in lines
    for name in sorted(set(str(value) for value in (deleted_vlan_names or []))):
        checks["vlan_%s_deleted" % name] = not any(
            line.startswith("set vlans %s " % name) for line in lines
        )
    return {
        "checks": checks,
        "result": "PASS" if all(checks.values()) else "FAIL",
        "port_states": port_states,
    }
