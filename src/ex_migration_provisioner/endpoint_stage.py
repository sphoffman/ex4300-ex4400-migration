from __future__ import annotations

import json
import re
from collections import defaultdict

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)
from ex_migration_discovery.normalize import normalize_mac
from ex_migration_discovery.parsers import parse_mac_table_text

from .core import ProvisioningError


_EDGE = re.compile(r"^ge-(?P<member>\d+)/0/(?P<port>\d+)$")


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def validate_postcutover_access(profile):
    _require(profile.get("schema_version") == "1.0", "unsupported environment profile schema")
    environment = str(profile.get("environment") or "")
    _require(environment in ("lab", "production"), "environment profile must be lab or production")
    access = profile.get("postcutover_ex_access") or {}
    mode = str(access.get("mode") or "")
    _require(mode in ("direct-management", "transport-override"), "unsupported post-cutover EX access mode")
    port = int(access.get("port", 830))
    _require(1 <= port <= 65535, "invalid post-cutover EX NETCONF port")
    if mode == "transport-override":
        _require(environment == "lab", "post-cutover transport override is permitted only in lab")
        _require(str(access.get("transport_address") or "").strip(), "lab transport override address is required")
    else:
        _require(environment == "production" or environment == "lab", "invalid direct-management environment")
    return profile


def resolve_postcutover_access(profile, management_ip):
    validate_postcutover_access(profile)
    access = profile["postcutover_ex_access"]
    mode = access["mode"]
    return {
        "environment": profile["environment"],
        "mode": mode,
        "logical_address": str(management_ip),
        "transport_address": (
            str(access["transport_address"])
            if mode == "transport-override"
            else str(management_ip)
        ),
        "port": int(access.get("port", 830)),
        "allow_vjunos_switch": mode == "transport-override",
    }


def qfx_plan_for_transaction(migration_root, transaction, approved_plan_digest):
    qfx_plan_id = str(transaction.get("qfx_plan_id") or "")
    _require(qfx_plan_id, "QFX transaction has no QFX VLAN plan ID")
    directory = migration_root / "qfx-vlan-plans" / qfx_plan_id
    path = directory / "plan.json"
    _require(path.is_file(), "QFX transaction references a missing VLAN plan")
    integrity = read_json(directory / "integrity.json")
    _require(integrity.get("plan.json") == sha256_file(path), "QFX VLAN plan integrity validation failed")
    value = read_json(path)
    _require(value.get("migration_id") == migration_root.name, "QFX VLAN plan migration ID mismatch")
    _require(value.get("result") == "PASS", "QFX VLAN plan did not pass")
    _require(
        value.get("inputs", {}).get("migration_plan_digest") == approved_plan_digest,
        "QFX transaction is bound to a different approved migration plan",
    )
    return {
        "plan": value,
        "plan_path": path,
        "plan_digest": sha256_file(path),
    }


def _vlan_by_id(plan):
    values = defaultdict(list)
    for item in plan.get("vlan_intents", []):
        vlan_id = item.get("vlan_id")
        if vlan_id is not None:
            values[int(vlan_id)].append(str(item.get("name") or ""))
    result = {}
    for vlan_id, names in values.items():
        unique = sorted({name for name in names if name})
        _require(len(unique) == 1, "approved plan has ambiguous VLAN ID %s" % vlan_id)
        result[vlan_id] = unique[0]
    return result


def _eligible_edge(interface, recovery_interface, uplink_interfaces=None):
    match = _EDGE.fullmatch(str(interface or ""))
    if not match:
        return False
    port = int(match.group("port"))
    excluded = {str(value) for value in (uplink_interfaces or [])}
    return 0 <= port <= 47 and interface != recovery_interface and interface not in excluded


def _normalize_expected_macs(port):
    values = []
    for value in port.get("endpoint_macs", []):
        try:
            values.append(normalize_mac(str(value)))
        except ValueError:
            raise ProvisioningError(
                "approved endpoint intent for %s contains invalid MAC %r"
                % (port.get("old_interface"), value)
            )
    return sorted(set(values))


def _description_statement(interface, description):
    value = str(description or "").strip()
    if not value:
        return None
    return "set interfaces %s description %s" % (interface, json.dumps(value))


def committed_endpoint_state(migration_root, approved_plan_digest):
    """Return integrity-valid committed endpoint mappings for the approved plan.

    This is historical completion evidence only. The caller must still reconcile
    each mapping against current committed EX configuration before skipping it.
    """
    by_old = {}
    by_new = {}
    transaction_ids = []
    root = migration_root / "endpoint-transactions"
    for tx_path in sorted(root.glob("*/transaction.json")):
        directory = tx_path.parent
        integrity_path = directory / "integrity.json"
        diff_path = directory / "candidate.diff"
        _require(integrity_path.is_file(), "endpoint transaction integrity record is missing")
        integrity = read_json(integrity_path)
        _require(
            integrity.get("transaction.json") == sha256_file(tx_path),
            "endpoint transaction integrity validation failed for %s" % directory.name,
        )
        if diff_path.is_file():
            _require(
                integrity.get("candidate.diff") == sha256_file(diff_path),
                "endpoint candidate diff integrity validation failed for %s" % directory.name,
            )
        tx = read_json(tx_path)
        if tx.get("migration_id") != migration_root.name:
            continue
        if tx.get("commit", {}).get("status") != "COMMITTED_AND_CONFIRMED":
            continue
        if tx.get("commit", {}).get("confirmed") is not True:
            continue
        if tx.get("validation", {}).get("result") != "PASS":
            continue

        correlation_id = str(tx.get("correlation_id") or "")
        _require(correlation_id, "committed endpoint transaction has no correlation ID")
        correlation_dir = migration_root / "endpoint-correlations" / correlation_id
        correlation_path = correlation_dir / "correlation.json"
        correlation_integrity_path = correlation_dir / "integrity.json"
        _require(correlation_path.is_file(), "committed endpoint transaction correlation is missing")
        _require(correlation_integrity_path.is_file(), "endpoint correlation integrity record is missing")
        correlation_integrity = read_json(correlation_integrity_path)
        _require(
            correlation_integrity.get("correlation.json") == sha256_file(correlation_path),
            "endpoint correlation integrity validation failed for %s" % correlation_id,
        )
        correlation = read_json(correlation_path)
        _require(
            correlation.get("inputs", {}).get("approved_plan_digest") == approved_plan_digest,
            "committed endpoint transaction is bound to a different approved migration plan",
        )

        transaction_id = str(tx.get("transaction_id") or directory.name)
        for row in tx.get("activated", []):
            old_interface = str(row.get("old_interface") or "")
            new_interface = str(row.get("new_interface") or "")
            _require(old_interface and new_interface, "committed endpoint transaction contains an incomplete mapping")
            normalized = dict(row)
            normalized["transaction_id"] = transaction_id
            previous = by_old.get(old_interface)
            if previous is not None:
                _require(
                    previous.get("new_interface") == new_interface,
                    "committed endpoint history maps %s to multiple new interfaces" % old_interface,
                )
                continue
            claimed = by_new.get(new_interface)
            _require(
                claimed is None or claimed == old_interface,
                "committed endpoint history maps multiple old interfaces to %s" % new_interface,
            )
            by_old[old_interface] = normalized
            by_new[new_interface] = old_interface
        transaction_ids.append(transaction_id)

    return {
        "by_old": by_old,
        "by_new": by_new,
        "completed": [by_old[key] for key in sorted(by_old)],
        "transaction_ids": sorted(set(transaction_ids)),
    }


def detect_silent_up_ports(
    terse_text,
    mac_table_text,
    recovery_interface,
    uplink_interfaces=None,
    completed_by_new=None,
):
    """Find eligible physical GE ports that are up/up but learn no dynamic MAC."""
    dynamic_ports = set()
    for row in parse_mac_table_text(
        mac_table_text or "",
        utc_now(),
        "post-cutover-ex4400-silent-port-scan",
    ):
        if row.mac_type == "dynamic":
            dynamic_ports.add(str(row.physical_interface or ""))

    completed = dict(completed_by_new or {})
    values = []
    seen = set()
    pattern = re.compile(r"^(ge-\d+/0/\d+)\s+up\s+up(?:\s|$)")
    for raw in str(terse_text or "").splitlines():
        match = pattern.match(raw.strip())
        if not match:
            continue
        interface = match.group(1)
        if interface in seen:
            continue
        seen.add(interface)
        if not _eligible_edge(interface, recovery_interface, uplink_interfaces):
            continue
        if interface in dynamic_ports:
            continue
        values.append({
            "interface": interface,
            "completed_old_interface": completed.get(interface),
        })
    return sorted(values, key=lambda item: item["interface"])


def correlate_endpoint_intent(
    plan,
    mac_table_text,
    recovery_interface,
    management_vlan_id,
    voice_vlan_id,
    temporary_recovery_vlan_id,
    observed_at=None,
    prestage_access_vlan_id=None,
    uplink_interfaces=None,
    completed=None,
):
    vlan_names = _vlan_by_id(plan)
    observations = parse_mac_table_text(
        mac_table_text or "",
        observed_at,
        "post-cutover-ex4400-mac-table",
    )

    prestage_id = int(prestage_access_vlan_id) if prestage_access_vlan_id is not None else None
    uplinks = [str(value) for value in (uplink_interfaces or [])]
    completed_by_old = dict(completed or {})
    completed_by_new = {
        str(row.get("new_interface")): old_interface
        for old_interface, row in completed_by_old.items()
        if row.get("new_interface")
    }

    by_mac = defaultdict(set)
    observed_rows = []
    for item in observations:
        if item.mac_type != "dynamic":
            continue
        physical = str(item.physical_interface or "")
        if not _eligible_edge(physical, recovery_interface, uplinks):
            continue
        by_mac[item.mac].add(physical)
        observed_rows.append({
            "mac": item.mac,
            "vlan_id": item.vlan.vlan_id,
            "vlan_name": item.vlan.name,
            "physical_interface": physical,
        })

    candidates = []
    holds = []
    for port in plan.get("port_intents", []):
        if port.get("planned_action") != "CORRELATE_AFTER_CABLE_MOVE":
            continue
        old_interface = str(port.get("old_interface") or "")
        if old_interface in completed_by_old:
            continue
        expected_macs = _normalize_expected_macs(port)
        supporting = {}
        interfaces = set()
        for mac in expected_macs:
            matches = sorted(by_mac.get(mac, set()))
            if matches:
                supporting[mac] = matches
                interfaces.update(matches)

        if not interfaces:
            holds.append({
                "old_interface": old_interface,
                "reason": "NO_APPROVED_MAC_OBSERVED_POST_MOVE",
                "expected_macs": expected_macs,
                "observed_support": supporting,
            })
            continue
        if len(interfaces) != 1:
            holds.append({
                "old_interface": old_interface,
                "reason": "APPROVED_MACS_MAP_TO_MULTIPLE_NEW_PORTS",
                "expected_macs": expected_macs,
                "observed_support": supporting,
                "candidate_new_interfaces": sorted(interfaces),
            })
            continue

        new_interface = next(iter(interfaces))
        if new_interface in completed_by_new:
            holds.append({
                "old_interface": old_interface,
                "reason": "NEW_PORT_ALREADY_ASSIGNED_TO_COMPLETED_INTENT",
                "expected_macs": expected_macs,
                "observed_support": supporting,
                "candidate_new_interfaces": [new_interface],
                "completed_old_interface": completed_by_new[new_interface],
            })
            continue

        vlan_id = port.get("configured_data_vlan_id")
        if vlan_id is None:
            holds.append({
                "old_interface": old_interface,
                "reason": "NO_CONFIGURED_DATA_VLAN",
                "expected_macs": expected_macs,
                "candidate_new_interfaces": [new_interface],
            })
            continue
        vlan_id = int(vlan_id)
        infrastructure_ids = {
            int(management_vlan_id),
            int(voice_vlan_id),
            int(temporary_recovery_vlan_id),
        }
        if prestage_id is not None:
            infrastructure_ids.add(prestage_id)
        if vlan_id in infrastructure_ids:
            holds.append({
                "old_interface": old_interface,
                "reason": "DATA_VLAN_COLLIDES_WITH_INFRASTRUCTURE_VLAN",
                "vlan_id": vlan_id,
                "candidate_new_interfaces": [new_interface],
            })
            continue
        vlan_name = vlan_names.get(vlan_id)
        if not vlan_name:
            holds.append({
                "old_interface": old_interface,
                "reason": "DATA_VLAN_NOT_RESOLVED_IN_APPROVED_PLAN",
                "vlan_id": vlan_id,
                "candidate_new_interfaces": [new_interface],
            })
            continue

        statements = []
        description_statement = _description_statement(new_interface, port.get("description"))
        if description_statement:
            statements.append(description_statement)
        statements.append(
            "set interfaces %s unit 0 family ethernet-switching vlan members %s"
            % (new_interface, vlan_name)
        )
        candidates.append({
            "old_interface": old_interface,
            "new_interface": new_interface,
            "description": port.get("description"),
            "data_vlan_id": vlan_id,
            "data_vlan_name": vlan_name,
            "expected_macs": expected_macs,
            "observed_support": supporting,
            "statements": statements,
        })

    by_new = defaultdict(list)
    for item in candidates:
        by_new[item["new_interface"]].append(item)
    conflicted = {interface for interface, rows in by_new.items() if len(rows) > 1}
    if conflicted:
        keep = []
        for item in candidates:
            if item["new_interface"] not in conflicted:
                keep.append(item)
                continue
            holds.append({
                "old_interface": item["old_interface"],
                "reason": "MULTIPLE_APPROVED_PORT_INTENTS_MAP_TO_SAME_NEW_PORT",
                "candidate_new_interfaces": [item["new_interface"]],
                "expected_macs": item["expected_macs"],
            })
        candidates = keep

    return {
        "completed": [completed_by_old[key] for key in sorted(completed_by_old)],
        "activated": sorted(candidates, key=lambda item: item["old_interface"]),
        "holds": sorted(holds, key=lambda item: (item["old_interface"], item["reason"])),
        "observed_relevant_macs": sorted(
            observed_rows,
            key=lambda item: (item["physical_interface"], item["mac"], item.get("vlan_id") or -1),
        ),
    }


def build_correlation_artifact(
    migration_id,
    approved_plan,
    approved_plan_digest,
    identity,
    identity_digest,
    qfx_transaction,
    qfx_transaction_digest,
    qfx_plan_digest,
    environment_profile_digest,
    access,
    correlation,
    mac_table_text,
    terse_text=None,
    created_at=None,
):
    mac_digest = sha256_bytes((mac_table_text or "").encode("utf-8"))
    terse_digest = sha256_bytes((terse_text or "").encode("utf-8"))
    key = {
        "migration_id": migration_id,
        "approved_plan_digest": approved_plan_digest,
        "identity_id": identity.get("identity_id"),
        "identity_digest": identity_digest,
        "qfx_transaction_id": qfx_transaction.get("transaction_id"),
        "qfx_transaction_digest": qfx_transaction_digest,
        "qfx_plan_digest": qfx_plan_digest,
        "environment_profile_digest": environment_profile_digest,
        "access": access,
        "correlation": correlation,
        "mac_table_sha256": mac_digest,
        "interfaces_terse_sha256": terse_digest,
    }
    correlation_id = sha256_bytes(canonical_bytes(key))[:16]
    result = "PASS" if correlation["activated"] or not correlation["holds"] else "HOLD"
    return {
        "schema_version": "1.1",
        "correlation_id": correlation_id,
        "migration_id": migration_id,
        "created_at": created_at or utc_now(),
        "inputs": {
            "approved_plan_id": approved_plan.get("plan_id"),
            "approved_plan_digest": approved_plan_digest,
            "identity_id": identity.get("identity_id"),
            "identity_digest": identity_digest,
            "qfx_transaction_id": qfx_transaction.get("transaction_id"),
            "qfx_transaction_digest": qfx_transaction_digest,
            "qfx_plan_digest": qfx_plan_digest,
            "environment_profile_digest": environment_profile_digest,
        },
        "access": access,
        "correlation": correlation,
        "mac_table_sha256": mac_digest,
        "interfaces_terse_sha256": terse_digest,
        "result": result,
        "statistics": {
            "completed": len(correlation.get("completed", [])),
            "new_activations": len(correlation["activated"]),
            "holds": len(correlation["holds"]),
            "silent_up_ports": len(correlation.get("silent_up_ports", [])),
        },
        "safety": {
            "read_only_observation": True,
            "unambiguous_mac_correlation_required": True,
            "recovery_interface_excluded": True,
            "historical_completion_reconciled_to_live_config": True,
            "ex4400_writes_authorized": False,
        },
    }


def write_correlation(migration_root, value, mac_table_text, terse_text=None):
    _require(value.get("result") in ("PASS", "HOLD"), "invalid endpoint correlation result")
    destination = migration_root / "endpoint-correlations" / value["correlation_id"]
    record_path = destination / "correlation.json"
    mac_path = destination / "mac-table.txt"
    terse_path = destination / "interfaces-terse.txt"
    normalized_mac = str(mac_table_text or "")
    if normalized_mac and not normalized_mac.endswith("\n"):
        normalized_mac += "\n"
    normalized_terse = str(terse_text or "")
    if normalized_terse and not normalized_terse.endswith("\n"):
        normalized_terse += "\n"

    if record_path.is_file():
        integrity = read_json(destination / "integrity.json")
        _require(integrity.get("correlation.json") == sha256_file(record_path), "endpoint correlation integrity failed")
        _require(integrity.get("mac-table.txt") == sha256_file(mac_path), "endpoint MAC evidence integrity failed")
        if value.get("schema_version") == "1.1":
            _require(terse_path.is_file(), "endpoint interface-state evidence is missing")
            _require(
                integrity.get("interfaces-terse.txt") == sha256_file(terse_path),
                "endpoint interface-state evidence integrity failed",
            )
        existing = read_json(record_path)
        comparable_existing = dict(existing)
        comparable_new = dict(value)
        comparable_existing.pop("created_at", None)
        comparable_new.pop("created_at", None)
        _require(comparable_existing == comparable_new, "existing endpoint correlation ID has different content")
        _require(mac_path.read_text(encoding="utf-8") == normalized_mac, "existing endpoint correlation MAC evidence changed")
        if value.get("schema_version") == "1.1":
            _require(
                terse_path.read_text(encoding="utf-8") == normalized_terse,
                "existing endpoint interface-state evidence changed",
            )
        return destination, existing, "UNCHANGED"

    destination.mkdir(parents=True, exist_ok=False)
    mac_path.write_text(normalized_mac, encoding="utf-8")
    if value.get("schema_version") == "1.1":
        terse_path.write_text(normalized_terse, encoding="utf-8")
    atomic_json(record_path, value)
    integrity = {
        "correlation.json": sha256_file(record_path),
        "mac-table.txt": sha256_file(mac_path),
    }
    if value.get("schema_version") == "1.1":
        integrity["interfaces-terse.txt"] = sha256_file(terse_path)
    atomic_json(destination / "integrity.json", integrity)
    return destination, value, "CREATED"


def build_endpoint_transaction(correlation, candidate_diff, approved_at, confirm_minutes):
    diff_digest = sha256_bytes(candidate_diff.encode("utf-8"))
    key = {
        "migration_id": correlation["migration_id"],
        "correlation_id": correlation["correlation_id"],
        "candidate_diff_sha256": diff_digest,
    }
    transaction_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "transaction_id": transaction_id,
        "migration_id": correlation["migration_id"],
        "correlation_id": correlation["correlation_id"],
        "approved_at": approved_at,
        "confirm_minutes": int(confirm_minutes),
        "candidate_diff_sha256": diff_digest,
        "activated": correlation["correlation"]["activated"],
        "holds": correlation["correlation"]["holds"],
        "commit": {
            "status": "APPROVED_PENDING_COMMIT",
            "confirmed": False,
        },
        "validation": {
            "result": "PENDING",
            "checks": [],
            "endpoint_evidence": [],
        },
        "safety": {
            "commit_confirmed_required": True,
            "qfx_writes_authorized": False,
            "temporary_recovery_vlan_cleanup_authorized": False,
        },
    }


def persist_endpoint_transaction(migration_root, transaction, candidate_diff):
    destination = migration_root / "endpoint-transactions" / transaction["transaction_id"]
    destination.mkdir(parents=True, exist_ok=True)
    diff_path = destination / "candidate.diff"
    normalized = str(candidate_diff or "")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    if diff_path.exists():
        _require(diff_path.read_text(encoding="utf-8") == normalized, "endpoint transaction candidate diff changed")
    else:
        diff_path.write_text(normalized, encoding="utf-8")
    tx_path = destination / "transaction.json"
    atomic_json(tx_path, transaction)
    atomic_json(destination / "integrity.json", {
        "transaction.json": sha256_file(tx_path),
        "candidate.diff": sha256_file(diff_path),
    })
    return destination
