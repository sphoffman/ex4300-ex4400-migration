from __future__ import annotations

import re

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)

from .core import ProvisioningError


_MEMBER = re.compile(
    r"(?m)^set interfaces (?P<ae>ae\d+) unit 0 family ethernet-switching vlan members (?P<value>\S+)\s*$"
)
_VLAN_DEF = re.compile(
    r"(?m)^set (?:routing-instances \S+ )?vlans (?P<name>\S+) vlan-id (?P<id>\d+)\s*$"
)


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def required_endpoint_interfaces(plan):
    correlate = []
    holds = []
    for item in plan.get("port_intents", []):
        action = item.get("planned_action")
        interface = str(item.get("old_interface") or "")
        if action == "CORRELATE_AFTER_CABLE_MOVE":
            correlate.append(interface)
        elif action == "HOLD_FOR_OPERATOR_RESOLUTION":
            holds.append(interface)
    return {
        "correlate": sorted(set(correlate)),
        "holds": sorted(set(holds)),
    }


def ex_cleanup_statements(
    recovery_interface,
    recovery_vlan_name,
    recovery_port_already_disabled=False,
    recovery_required=True,
):
    # Historical recovery cleanup remains supported only for old artifacts that
    # explicitly require it. Current migrations treat temporary fxp0 management
    # as external and therefore generate no recovery/temp-management writes.
    if not recovery_required:
        return []
    _require(recovery_interface, "recovery interface is required")
    _require(recovery_vlan_name, "recovery VLAN name is required")
    statements = []
    if not recovery_port_already_disabled:
        statements.append("set interfaces %s disable" % recovery_interface)
    return statements


def qfx_cleanup_statements(ae_interface, recovery_vlan_name, recovery_required=True):
    if not recovery_required:
        return []
    return [
        "delete interfaces %s unit 0 family ethernet-switching vlan members %s"
        % (ae_interface, recovery_vlan_name)
    ]


def inverse_statements(statements):
    result = []
    for statement in reversed(list(statements)):
        if statement.startswith("delete "):
            result.append("set " + statement[len("delete "):])
        elif statement.startswith("set "):
            result.append("delete " + statement[len("set "):])
        else:
            raise ProvisioningError("cleanup statement is neither set nor delete")
    return result


def complete_stale_vlan_object_deletes(statements, access_hardening):
    result = list(statements)
    for item in access_hardening.get("stale_vlans", {}).get("delete", []):
        name = str(item.get("name") or "")
        _require(name, "proven-unused VLAN cleanup record is missing a name")
        statement = "delete vlans %s" % name
        if statement not in result:
            result.append(statement)
    return result


def ex_recovery_state(config_text, recovery_interface, recovery_vlan_name, recovery_vlan_id, prestage_vlan_id):
    """Compatibility observation for historical cleanup artifacts.

    Current migrations pass an external sentinel and do not make decisions from
    temporary-management state.
    """
    lines = {line.strip() for line in str(config_text or "").splitlines() if line.strip()}
    disabled = "set interfaces %s disable" % recovery_interface
    member = (
        "set interfaces %s unit 0 family ethernet-switching vlan members %s"
        % (recovery_interface, recovery_vlan_name)
    )
    vlan = "set vlans %s vlan-id %s" % (recovery_vlan_name, int(recovery_vlan_id))
    holding = "set vlans default vlan-id %s" % int(prestage_vlan_id)
    other_members = sorted(
        line for line in lines
        if re.match(
            r"^set interfaces \S+ unit 0 family ethernet-switching vlan members %s$"
            % re.escape(recovery_vlan_name),
            line,
        )
        and line != member
    )
    return {
        "recovery_port_disabled": disabled in lines,
        "recovery_port_membership_present": member in lines,
        "recovery_vlan_definition_present": vlan in lines,
        "holding_default_vlan_present": holding in lines,
        "unexpected_other_recovery_memberships": other_members,
    }


def qfx_vlan_ids(ae_config_text, vlan_config_text, ae_interface):
    definitions = {}
    ambiguous = set()
    for match in _VLAN_DEF.finditer(str(vlan_config_text or "")):
        name = match.group("name")
        vlan_id = int(match.group("id"))
        if name in definitions and definitions[name] != vlan_id:
            ambiguous.add(name)
        else:
            definitions[name] = vlan_id

    tokens = [
        match.group("value")
        for match in _MEMBER.finditer(str(ae_config_text or ""))
        if match.group("ae") == ae_interface
    ]
    _require("all" not in tokens, "%s VLAN membership uses 'all'; cleanup cannot prove exact scope" % ae_interface)
    ids = []
    unresolved = []
    for token in tokens:
        if token.isdigit():
            ids.append(int(token))
        elif token in ambiguous:
            unresolved.append("%s(ambiguous)" % token)
        elif token in definitions:
            ids.append(definitions[token])
        else:
            unresolved.append(token)
    return {
        "tokens": sorted(set(tokens)),
        "vlan_ids": sorted(set(ids)),
        "unresolved": sorted(set(unresolved)),
        "definitions": dict(sorted(definitions.items())),
        "ambiguous_definitions": sorted(ambiguous),
    }


def validate_pre_cleanup(
    plan,
    live_completed_by_old,
    ex_state,
    qfx_states,
    management_vlan_id,
    recovery_vlan_id,
    recovery_vlan_name,
    required_production_vlan_ids,
    access_hardening,
    recovery_required=True,
):
    endpoint = required_endpoint_interfaces(plan)
    missing_completed = sorted(
        interface for interface in endpoint["correlate"]
        if interface not in live_completed_by_old
    )
    checks = {
        "no_operator_hold_intents": not endpoint["holds"],
        "all_required_endpoint_intents_live": not missing_completed,
        "access_hardening_classification_pass": access_hardening.get("result") == "PASS",
        "ex_holding_default_vlan_present": bool(ex_state.get("holding_default_vlan_present")),
    }
    if recovery_required:
        checks["ex_no_other_recovery_memberships"] = not ex_state.get("unexpected_other_recovery_memberships")
        checks["ex_recovery_port_membership_present"] = bool(ex_state.get("recovery_port_membership_present"))
        checks["ex_recovery_vlan_definition_present"] = bool(ex_state.get("recovery_vlan_definition_present"))

    required_qfx = set(int(value) for value in required_production_vlan_ids)
    required_qfx.add(int(management_vlan_id))
    if recovery_required:
        required_qfx.add(int(recovery_vlan_id))
    for role, state in sorted(qfx_states.items()):
        ids = set(state.get("vlan_ids", []))
        checks["%s_vlan_membership_resolved" % role] = not state.get("unresolved")
        checks["%s_required_vlans_present" % role] = required_qfx <= ids
        if recovery_required:
            checks["%s_recovery_vlan_present" % role] = int(recovery_vlan_id) in ids
            checks["%s_recovery_vlan_definition_present" % role] = (
                state.get("definitions", {}).get(recovery_vlan_name) == int(recovery_vlan_id)
            )
        checks["%s_topology_validation_pass" % role] = state.get("topology_result") == "PASS"
    return {
        "checks": checks,
        "missing_completed_endpoint_intents": missing_completed,
        "operator_hold_intents": endpoint["holds"],
        "access_hardening_blockers": list(access_hardening.get("blockers", [])),
        "recovery_required": bool(recovery_required),
        "result": "PASS" if all(checks.values()) else "FAIL",
    }


def validate_post_cleanup(
    plan,
    live_completed_by_old,
    ex_state,
    qfx_states,
    management_vlan_id,
    recovery_vlan_id,
    recovery_vlan_name,
    required_production_vlan_ids,
    access_hardening_validation,
    recovery_required=True,
):
    endpoint = required_endpoint_interfaces(plan)
    missing_completed = sorted(
        interface for interface in endpoint["correlate"]
        if interface not in live_completed_by_old
    )
    checks = {
        "no_operator_hold_intents": not endpoint["holds"],
        "all_required_endpoint_intents_still_live": not missing_completed,
        "access_hardening_validation_pass": access_hardening_validation.get("result") == "PASS",
        "ex_holding_default_vlan_preserved": bool(ex_state.get("holding_default_vlan_present")),
    }
    if recovery_required:
        checks["ex_recovery_port_disabled"] = bool(ex_state.get("recovery_port_disabled"))
        checks["ex_no_other_recovery_memberships"] = not ex_state.get("unexpected_other_recovery_memberships")
        checks["ex_recovery_port_membership_preserved"] = bool(ex_state.get("recovery_port_membership_present"))
        checks["ex_recovery_vlan_definition_preserved"] = bool(ex_state.get("recovery_vlan_definition_present"))

    required_qfx = set(int(value) for value in required_production_vlan_ids)
    required_qfx.add(int(management_vlan_id))
    for role, state in sorted(qfx_states.items()):
        ids = set(state.get("vlan_ids", []))
        checks["%s_vlan_membership_resolved" % role] = not state.get("unresolved")
        checks["%s_required_production_and_management_preserved" % role] = required_qfx <= ids
        if recovery_required:
            checks["%s_recovery_vlan_absent" % role] = int(recovery_vlan_id) not in ids
            checks["%s_recovery_vlan_definition_preserved" % role] = (
                state.get("definitions", {}).get(recovery_vlan_name) == int(recovery_vlan_id)
            )
        checks["%s_topology_validation_pass" % role] = state.get("topology_result") == "PASS"
    return {
        "checks": checks,
        "missing_completed_endpoint_intents": missing_completed,
        "operator_hold_intents": endpoint["holds"],
        "access_hardening_validation": access_hardening_validation,
        "recovery_required": bool(recovery_required),
        "result": "PASS" if all(checks.values()) else "FAIL",
    }


def build_cleanup_plan(
    migration_id,
    approved_plan,
    approved_plan_digest,
    package_id,
    package_digest,
    identity_id,
    identity_digest,
    qfx_transaction_id,
    qfx_transaction_digest,
    qfx_plan_id,
    site_policy_id,
    site_policy_digest,
    recovery_interface,
    recovery_vlan_name,
    recovery_vlan_id,
    prestage_vlan_id,
    recovery_port_already_disabled,
    qfx_ae_by_role,
    precheck,
    access_hardening,
    access_hardening_statements,
    production_vlan_names,
    recovery_required=True,
    created_at=None,
):
    _require(precheck.get("result") == "PASS", "final cleanup prechecks did not pass")
    hardened_statements = complete_stale_vlan_object_deletes(
        access_hardening_statements,
        access_hardening,
    )
    ex_statements = list(hardened_statements) + ex_cleanup_statements(
        recovery_interface,
        recovery_vlan_name,
        recovery_port_already_disabled=recovery_port_already_disabled,
        recovery_required=recovery_required,
    )
    qfx_devices = []
    for role in sorted(qfx_ae_by_role):
        statements = qfx_cleanup_statements(
            qfx_ae_by_role[role],
            recovery_vlan_name,
            recovery_required=recovery_required,
        )
        qfx_devices.append({
            "role": role,
            "ae_interface": qfx_ae_by_role[role],
            "statements": statements,
            "restore_statements": inverse_statements(statements),
        })
    inputs = {
        "approved_plan_digest": approved_plan_digest,
        "package_id": package_id,
        "package_digest": package_digest,
        "identity_id": identity_id,
        "identity_digest": identity_digest,
        "qfx_transaction_id": qfx_transaction_id,
        "qfx_transaction_digest": qfx_transaction_digest,
        "qfx_plan_id": qfx_plan_id,
        "site_policy_id": site_policy_id,
        "site_policy_digest": site_policy_digest,
    }
    key = {
        "migration_id": migration_id,
        "inputs": inputs,
        "recovery_interface": recovery_interface,
        "recovery_vlan_name": recovery_vlan_name,
        "recovery_vlan_id": int(recovery_vlan_id),
        "recovery_required": bool(recovery_required),
        "recovery_port_already_disabled": bool(recovery_port_already_disabled),
        "production_vlan_names": sorted(set(production_vlan_names)),
        "access_hardening": access_hardening,
        "ex_statements": ex_statements,
        "qfx_devices": qfx_devices,
    }
    plan_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "cleanup_plan_id": plan_id,
        "migration_id": migration_id,
        "created_at": created_at or utc_now(),
        "inputs": inputs,
        # This object remains for cleanup schema compatibility. Current
        # migrations set required=false and no device statement is generated
        # from these fields.
        "recovery": {
            "required": bool(recovery_required),
            "interface": recovery_interface,
            "vlan_name": recovery_vlan_name,
            "vlan_id": int(recovery_vlan_id),
            "prestage_default_vlan_id": int(prestage_vlan_id),
            "initially_disabled": bool(recovery_port_already_disabled),
            "final_state": (
                "DISABLED_LOCAL_RECOVERY_PRESERVED"
                if recovery_required
                else "EXTERNAL_NOT_MANAGED"
            ),
        },
        "access_hardening": access_hardening,
        "production_vlan_names": sorted(set(production_vlan_names)),
        "ex4400": {
            "statements": ex_statements,
            "restore_statements": inverse_statements(ex_statements),
        },
        "qfx_devices": qfx_devices,
        "precheck": precheck,
        "result": "PASS",
        "safety": {
            "terminal_recovery_window_action": bool(recovery_required),
            "old_ex_vme_recovery_configuration_preserved": True,
            "ex4400_recovery_port_disabled": bool(recovery_required),
            "ex4400_recovery_vlan_configuration_preserved": bool(recovery_required),
            "qfx_global_recovery_vlan_definition_preserved": True,
            "endpoint_configuration_must_remain_present": True,
            "configured_unused_ex_ports_disabled": True,
            "inactive_default_vlan_removed_from_uplink_trunk": True,
            "template_owned_edge_range_preserved": True,
            "broad_edge_voice_policy_preserved": True,
            "only_proven_unused_data_vlans_removed": True,
            "commit_confirmed_required_on_all_written_devices": True,
        },
    }


def write_cleanup_plan(migration_root, value):
    _require(value.get("result") == "PASS", "cleanup plan did not pass")
    destination = migration_root / "recovery-cleanup-plans" / value["cleanup_plan_id"]
    path = destination / "plan.json"
    if path.is_file():
        integrity = read_json(directory / "integrity.json")
        _require(integrity.get("plan.json") == sha256_file(path), "cleanup plan integrity failed")
        existing = read_json(path)
        comparable_existing = dict(existing)
        comparable_new = dict(value)
        comparable_existing.pop("created_at", None)
        comparable_new.pop("created_at", None)
        _require(comparable_existing == comparable_new, "existing cleanup plan ID has different content")
        return destination, existing, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(path, value)
    atomic_json(destination / "integrity.json", {"plan.json": sha256_file(path)})
    return destination, value, "CREATED"


def build_cleanup_transaction(cleanup_plan, candidate_diffs, approved_at, confirm_minutes):
    diff_digests = {
        role: sha256_bytes(str(candidate_diffs[role]).encode("utf-8"))
        for role in sorted(candidate_diffs)
    }
    key = {
        "migration_id": cleanup_plan["migration_id"],
        "cleanup_plan_id": cleanup_plan["cleanup_plan_id"],
        "candidate_diffs": diff_digests,
    }
    transaction_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "transaction_id": transaction_id,
        "migration_id": cleanup_plan["migration_id"],
        "cleanup_plan_id": cleanup_plan["cleanup_plan_id"],
        "approved_at": approved_at,
        "confirm_minutes": int(confirm_minutes),
        "inputs": dict(cleanup_plan["inputs"]),
        "candidate_diff_sha256": diff_digests,
        "devices": {
            role: {"commit_status": "NOT_STARTED"}
            for role in sorted(candidate_diffs)
        },
        "validation": {"result": "PENDING", "checks": {}},
        "status": "APPROVED_PENDING_COMMIT",
        "safety": dict(cleanup_plan["safety"]),
    }


def persist_cleanup_transaction(migration_root, transaction, candidate_diffs):
    destination = migration_root / "recovery-cleanup-transactions" / transaction["transaction_id"]
    destination.mkdir(parents=True, exist_ok=True)
    integrity = {}
    for role, text in sorted(candidate_diffs.items()):
        path = destination / ("%s.diff" % role)
        normalized = str(text or "")
        if normalized and not normalized.endswith("\n"):
            normalized += "\n"
        if path.is_file():
            _require(path.read_text(encoding="utf-8") == normalized, "cleanup candidate diff changed for %s" % role)
        else:
            path.write_text(normalized, encoding="utf-8")
        integrity[path.name] = sha256_file(path)
    tx_path = destination / "transaction.json"
    atomic_json(tx_path, transaction)
    integrity["transaction.json"] = sha256_file(tx_path)
    atomic_json(destination / "integrity.json", integrity)
    return destination


def committed_cleanup_transactions(migration_root, approved_plan_digest):
    values = []
    root = migration_root / "recovery-cleanup-transactions"
    if not root.is_dir():
        return values
    for tx_path in sorted(root.glob("*/transaction.json")):
        directory = tx_path.parent
        try:
            integrity = read_json(directory / "integrity.json")
            if integrity.get("transaction.json") != sha256_file(tx_path):
                continue
            tx = read_json(tx_path)
            if tx.get("migration_id") != migration_root.name:
                continue
            if tx.get("inputs", {}).get("approved_plan_digest") != approved_plan_digest:
                continue
            if tx.get("status") != "COMMITTED_AND_CONFIRMED":
                continue
            if tx.get("validation", {}).get("result") != "PASS":
                continue
            values.append({
                "transaction": tx,
                "transaction_path": tx_path,
                "transaction_digest": sha256_file(tx_path),
                "directory": directory,
            })
        except (OSError, ValueError):
            continue
    return sorted(
        values,
        key=lambda item: (
            item["transaction"].get("confirmed_at", ""),
            item["transaction"].get("transaction_id", ""),
        ),
        reverse=True,
    )
