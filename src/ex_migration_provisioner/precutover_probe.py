from __future__ import annotations

from pathlib import Path

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from ex_migration_discovery.parsers import (
    parse_interfaces_terse,
    parse_mac_table_text,
    parse_set_configuration,
)

from .core import ProvisioningError


SILENT_DISPOSITIONS = {"CONFIGURED_NO_MAC", "ACTIVE_UNASSIGNED_SILENT"}


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def analysis_for_approved_plan(migration_root, selected_plan):
    plan = selected_plan["plan"]
    inputs = plan.get("inputs", {})
    analysis_id = str(inputs.get("analysis_id") or "")
    expected_digest = str(inputs.get("analysis_digest") or "")
    _require(analysis_id, "approved migration plan has no source analysis ID")
    path = Path(migration_root) / "analyses" / analysis_id / "analysis.json"
    _require(path.is_file(), "approved migration plan source analysis is missing: %s" % path)
    actual_digest = sha256_file(path)
    _require(
        actual_digest == expected_digest,
        "approved migration plan source analysis failed digest validation",
    )
    value = read_json(path)
    analysis_migration_id = str(
        value.get("template_variables", {}).get("migration_id") or ""
    )
    _require(
        analysis_migration_id == str(plan.get("migration_id") or ""),
        "source analysis migration ID mismatch",
    )
    _require(value.get("analysis_id") == analysis_id, "source analysis ID mismatch")
    return value, path, actual_digest


def silent_candidates(analysis):
    rows = []
    for port in analysis.get("ports", []):
        disposition = str(port.get("disposition") or "")
        interface = str(port.get("interface") or "")
        if disposition not in SILENT_DISPOSITIONS or not interface:
            continue
        rows.append({
            "interface": interface,
            "analysis_disposition": disposition,
            "configured_data_vlan_id": port.get("configured_data_vlan_id"),
            "description": port.get("description"),
            "historical_observations": list(port.get("historical_observations") or []),
        })
    return sorted(rows, key=lambda item: item["interface"])


def live_candidate_state(config_text, terse_text, mac_detail_text, candidates, observed_at=None):
    interfaces, _vlans, _voice, _warnings = parse_set_configuration(config_text)
    parse_interfaces_terse(terse_text, interfaces)
    observations = parse_mac_table_text(
        mac_detail_text,
        observed_at or utc_now(),
        "live-precutover-probe",
        interfaces,
    )
    dynamic = {}
    for item in observations:
        if item.mac_type != "dynamic":
            continue
        dynamic.setdefault(item.physical_interface, set()).add(item.mac)

    rows = []
    for candidate in candidates:
        interface = candidate["interface"]
        state = interfaces.get(interface)
        live_vlan_id = None
        if state is not None and state.untagged_vlan is not None:
            live_vlan_id = state.untagged_vlan.vlan_id
        expected_vlan_id = candidate.get("configured_data_vlan_id")
        macs = sorted(dynamic.get(interface, set()))
        reason = None
        if state is None:
            reason = "INTERFACE_NOT_PRESENT"
        elif state.ae_parent:
            reason = "INTERFACE_NOW_IN_AE"
        elif state.effective_mode != "access":
            reason = "INTERFACE_NOT_ACCESS"
        elif expected_vlan_id != live_vlan_id:
            reason = "ACCESS_VLAN_CHANGED"
        elif state.admin_status != "up":
            reason = "INTERFACE_NOT_ADMIN_UP"
        elif state.oper_status != "up":
            reason = "INTERFACE_NOT_OPER_UP"
        elif macs:
            reason = "MAC_NOW_PRESENT"

        row = dict(candidate)
        row.update({
            "live_admin_status": state.admin_status if state else None,
            "live_oper_status": state.oper_status if state else None,
            "live_data_vlan_id": live_vlan_id,
            "live_dynamic_macs": macs,
            "eligible": reason is None,
            "skip_reason": reason,
        })
        rows.append(row)
    return rows


def eligible_interfaces(rows):
    return sorted(row["interface"] for row in rows if row.get("eligible"))


def discovered_candidate_macs(snapshot, candidate_interfaces):
    candidates = set(candidate_interfaces)
    values = {}
    for item in snapshot.get("mac_observations", []):
        interface = str(item.get("physical_interface") or "")
        mac = str(item.get("mac") or "")
        if interface not in candidates or not mac or item.get("mac_type") != "dynamic":
            continue
        vlan_id = item.get("vlan", {}).get("vlan_id")
        values.setdefault(interface, set()).add((mac, vlan_id))
    return {
        interface: [
            {"mac": mac, "vlan_id": vlan_id}
            for mac, vlan_id in sorted(items, key=lambda value: (value[0], value[1] or -1))
        ]
        for interface, items in sorted(values.items())
    }


def build_probe_record(
    migration_id,
    selected_plan,
    analysis,
    analysis_digest,
    source_address,
    source_hostname,
    initial_state,
    approved_interfaces,
    locked_state,
    collection_path,
    collection_snapshot,
    started_at,
    completed_at=None,
):
    discovered = discovered_candidate_macs(collection_snapshot, approved_interfaces)
    key = {
        "migration_id": migration_id,
        "approved_plan_digest": selected_plan["plan_digest"],
        "analysis_digest": analysis_digest,
        "started_at": started_at,
        "approved_interfaces": sorted(approved_interfaces),
    }
    probe_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "probe_id": probe_id,
        "migration_id": migration_id,
        "started_at": started_at,
        "completed_at": completed_at or utc_now(),
        "inputs": {
            "approved_plan_id": selected_plan["plan"].get("plan_id"),
            "approved_plan_digest": selected_plan["plan_digest"],
            "analysis_id": analysis.get("analysis_id"),
            "analysis_digest": analysis_digest,
        },
        "source_switch": {
            "address": source_address,
            "hostname": source_hostname,
        },
        "initial_candidates": initial_state,
        "approved_interfaces": sorted(approved_interfaces),
        "locked_recheck": locked_state,
        "post_bounce_collection": str(collection_path),
        "discovered_candidate_macs": discovered,
        "new_client_evidence_found": bool(discovered),
        "result": "PASS",
        "next_action": (
            "RERUN_ANALYZER_AND_PLANNER_BEFORE_CUTOVER"
            if discovered
            else "NO_NEW_CLIENT_EVIDENCE"
        ),
        "safety": {
            "candidate_source_bound_to_approved_plan_analysis": True,
            "live_recheck_required_before_write": True,
            "only_still_silent_admin_up_oper_up_access_ports_bounced": True,
            "source_switch_identity_validated": True,
            "post_bounce_evidence_is_normal_discovery_collection": True,
        },
    }


def write_probe_record(migration_root, value):
    destination = Path(migration_root) / "old-switch" / "precutover-probes" / value["probe_id"]
    path = destination / "probe.json"
    if path.is_file():
        integrity = read_json(destination / "integrity.json")
        _require(integrity.get("probe.json") == sha256_file(path), "pre-cutover probe integrity failed")
        existing = read_json(path)
        _require(existing == value, "existing pre-cutover probe ID has different content")
        return destination, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(path, value)
    atomic_json(destination / "integrity.json", {"probe.json": sha256_file(path)})
    return destination, "CREATED"
