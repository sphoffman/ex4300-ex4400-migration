from __future__ import annotations

from copy import deepcopy
from collections import defaultdict

from .core import AnalysisError, canonical_bytes, sha256_bytes


def _sorted_dicts(values):
    return sorted((deepcopy(value) for value in values or []), key=lambda value: canonical_bytes(value))


def _device_state(snapshot):
    """Return observed old-device identity, excluding tool-derived migration metadata."""
    device = snapshot.get("device", {})
    return {
        "hostname": device.get("hostname"),
        "model": device.get("model"),
        "serial_numbers": sorted(device.get("serial_numbers") or []),
        "configured_hostname": device.get("configured_hostname"),
    }


def _management_state(snapshot):
    management = snapshot.get("management", {})
    snmp = management.get("snmp", {}) or {}
    return {
        "vlan_name": management.get("vlan_name"),
        "vlan_id": management.get("vlan_id"),
        "l3_interface": management.get("l3_interface"),
        "addresses": sorted(management.get("addresses") or []),
        "production_ipv4": management.get("production_ipv4"),
        "default_gateway": management.get("default_gateway"),
        "fxp0_addresses": sorted(management.get("fxp0_addresses") or []),
        "mgmt_junos_default_gateways": sorted(management.get("mgmt_junos_default_gateways") or []),
        "snmp": {
            "name": snmp.get("name"),
            "location": snmp.get("location"),
            "engine_id_type": snmp.get("engine_id_type"),
            "engine_id": snmp.get("engine_id"),
            "v3_configured": snmp.get("v3_configured"),
        },
        "consistency": management.get("consistency"),
    }


def _interface_config(item):
    return {
        "description": item.get("description"),
        "ae_parent": item.get("ae_parent"),
        "effective_mode": item.get("effective_mode"),
        "untagged_vlan": deepcopy(item.get("untagged_vlan")),
        "tagged_vlans": _sorted_dicts(item.get("tagged_vlans") or []),
        "interface_ranges": sorted(item.get("interface_ranges") or []),
    }


def _interfaces_state(snapshot):
    return {
        item.get("physical_name"): _interface_config(item)
        for item in snapshot.get("interfaces", [])
        if item.get("physical_name")
    }


def _vlan_config(item):
    return {
        "name": item.get("name"),
        "vlan_id": item.get("vlan_id"),
        "configured": item.get("configured", True),
        "description": item.get("description"),
        "interfaces": _sorted_dicts(item.get("interfaces") or []),
        "irb_interface": item.get("irb_interface"),
        "purpose": item.get("purpose"),
        "dhcp_snooping_trusted_interfaces": sorted(item.get("dhcp_snooping_trusted_interfaces") or []),
    }


def _vlans_state(snapshot):
    return sorted(
        (_vlan_config(item) for item in snapshot.get("vlans", [])),
        key=lambda item: (item.get("vlan_id") is None, item.get("vlan_id") or 0, item.get("name") or ""),
    )


def _voice_state(snapshot):
    value = snapshot.get("voice_policy", {}) or {}
    return {
        "configured": value.get("configured"),
        "vlan_name": value.get("vlan_name"),
        "vlan_id": value.get("vlan_id"),
        "interface_selectors": sorted(value.get("interface_selectors") or []),
        "valid": value.get("valid"),
        "errors": sorted(value.get("errors") or []),
    }


def _variants(candidates, getter):
    values = {}
    for candidate in candidates:
        snapshot = candidate["snapshot"]
        state = getter(snapshot)
        digest = sha256_bytes(canonical_bytes(state))
        if digest not in values:
            values[digest] = {"value": state, "snapshot_ids": []}
        values[digest]["snapshot_ids"].append(snapshot["snapshot_id"])
    return [
        {"snapshot_ids": sorted(item["snapshot_ids"]), "value": item["value"]}
        for _digest, item in sorted(values.items())
    ]


def _finding(severity, code, subject, message, evidence):
    return {
        "severity": severity,
        "code": code,
        "subject": subject,
        "message": message,
        "evidence": evidence,
    }


def _endpoint_catalog(candidates):
    catalog = defaultdict(set)
    latest_rows = {}
    for candidate in candidates:
        snapshot = candidate["snapshot"]
        snapshot_id = snapshot["snapshot_id"]
        for row in snapshot.get("mac_observations", []):
            interface = row.get("physical_interface")
            mac = row.get("mac")
            vlan_id = (row.get("vlan") or {}).get("vlan_id")
            if not mac or not interface or vlan_id is None:
                continue
            key = (str(mac), int(vlan_id), str(interface))
            catalog[key].add(snapshot_id)
            row_key = (str(mac), int(vlan_id), str(interface), str(row.get("interface_class") or ""))
            current = latest_rows.get(row_key)
            row_stamp = str(row.get("observed_at") or snapshot.get("completed_at") or "")
            if current is None or row_stamp >= current[0]:
                latest_rows[row_key] = (row_stamp, deepcopy(row))
    rows = [
        {
            "mac": key[0],
            "vlan_id": key[1],
            "interface": key[2],
            "snapshot_ids": sorted(snapshot_ids),
        }
        for key, snapshot_ids in sorted(catalog.items(), key=lambda item: (item[0][2], item[0][0], item[0][1]))
    ]
    observations = [
        item[1]
        for _key, item in sorted(latest_rows.items(), key=lambda item: item[0])
    ]
    return rows, observations


def _interface_change_findings(candidates):
    names = sorted({
        item.get("physical_name")
        for candidate in candidates
        for item in candidate["snapshot"].get("interfaces", [])
        if item.get("physical_name")
    })
    findings = []
    changed = []
    states_by_snapshot = {
        candidate["snapshot"]["snapshot_id"]: _interfaces_state(candidate["snapshot"])
        for candidate in candidates
    }
    for name in names:
        variants = {}
        for candidate in candidates:
            snapshot_id = candidate["snapshot"]["snapshot_id"]
            value = states_by_snapshot[snapshot_id].get(name, {"state": "ABSENT"})
            digest = sha256_bytes(canonical_bytes(value))
            variants.setdefault(digest, {"value": value, "snapshot_ids": []})["snapshot_ids"].append(snapshot_id)
        if len(variants) > 1:
            evidence = [
                {"snapshot_ids": sorted(value["snapshot_ids"]), "value": value["value"]}
                for _digest, value in sorted(variants.items())
            ]
            changed.append(name)
            findings.append(_finding(
                "REVIEW",
                "INTERFACE_CONFIGURATION_CHANGED",
                name,
                "interface configuration changed across eligible discovery collections; latest eligible state is used as current configuration",
                evidence,
            ))
    return changed, findings


def build_composite_evidence(candidates, policy, policy_digest):
    eligible = [candidate for candidate in candidates if not candidate.get("blockers")]
    if not eligible:
        raise AnalysisError("no complete policy-eligible old-switch collections were found")
    eligible = sorted(eligible, key=lambda item: (item["snapshot"].get("completed_at", ""), item["snapshot"].get("snapshot_id", "")))
    migration_ids = {item["snapshot"].get("migration_id") for item in eligible}
    if len(migration_ids) != 1:
        raise AnalysisError("eligible collections do not share one migration ID")
    migration_id = next(iter(migration_ids))
    latest = eligible[-1]

    findings = []
    consistency = {}

    device_variants = _variants(eligible, _device_state)
    consistency["device_identity"] = "CONSISTENT" if len(device_variants) == 1 else "CONFLICT"
    if len(device_variants) > 1:
        findings.append(_finding(
            "BLOCKER", "DEVICE_IDENTITY_CHANGED", "device",
            "observed old-switch identity changed across eligible discovery collections",
            device_variants,
        ))

    management_variants = _variants(eligible, _management_state)
    consistency["management"] = "CONSISTENT" if len(management_variants) == 1 else "CONFLICT"
    if len(management_variants) > 1:
        findings.append(_finding(
            "BLOCKER", "MANAGEMENT_CONFIGURATION_CHANGED", "management",
            "management configuration changed across eligible discovery collections",
            management_variants,
        ))

    vlan_variants = _variants(eligible, _vlans_state)
    consistency["vlans"] = "CONSISTENT" if len(vlan_variants) == 1 else "CHANGED"
    if len(vlan_variants) > 1:
        findings.append(_finding(
            "REVIEW", "VLAN_CONFIGURATION_CHANGED", "vlans",
            "VLAN configuration changed across eligible discovery collections; latest eligible state is used as current configuration",
            vlan_variants,
        ))

    voice_variants = _variants(eligible, _voice_state)
    consistency["voice_policy"] = "CONSISTENT" if len(voice_variants) == 1 else "CHANGED"
    if len(voice_variants) > 1:
        findings.append(_finding(
            "REVIEW", "VOICE_POLICY_CHANGED", "voice-policy",
            "voice configuration changed across eligible discovery collections; latest eligible state is used as current configuration",
            voice_variants,
        ))

    changed_interfaces, interface_findings = _interface_change_findings(eligible)
    consistency["interfaces"] = "CONSISTENT" if not changed_interfaces else "CHANGED"
    findings.extend(interface_findings)

    version_variants = _variants(eligible, lambda snapshot: {"junos_version": snapshot.get("device", {}).get("junos_version")})
    consistency["junos_version"] = "CONSISTENT" if len(version_variants) == 1 else "CHANGED"
    if len(version_variants) > 1:
        findings.append(_finding(
            "REVIEW", "JUNOS_VERSION_CHANGED", "device",
            "Junos version changed across eligible discovery collections",
            version_variants,
        ))

    endpoint_catalog, composite_observations = _endpoint_catalog(eligible)
    mac_ports = defaultdict(set)
    for row in endpoint_catalog:
        mac_ports[row["mac"]].add(row["interface"])
    conflicting_macs = sorted(mac for mac, ports in mac_ports.items() if len(ports) > 1)

    collection_refs = [
        {
            "snapshot_id": item["snapshot"]["snapshot_id"],
            "snapshot_schema_version": item["snapshot"]["schema_version"],
            "collection_digest": item["envelope"]["collection_digest"],
            "started_at": item["snapshot"].get("started_at"),
            "completed_at": item["snapshot"].get("completed_at"),
        }
        for item in eligible
    ]
    evidence_body = {
        "schema_version": "1.0",
        "input_kind": "COMPOSITE_EVIDENCE_SET",
        "migration_id": migration_id,
        "policy_id": policy.get("policy_id"),
        "policy_digest": policy_digest,
        "collections": collection_refs,
        "observation_span": {
            "started_at": min(item["snapshot"].get("started_at", "") for item in eligible),
            "completed_at": max(item["snapshot"].get("completed_at", "") for item in eligible),
        },
        "current_configuration_source_snapshot_id": latest["snapshot"]["snapshot_id"],
        "configuration_consistency": consistency,
        "configuration_findings": findings,
        "endpoint_catalog": endpoint_catalog,
        "endpoint_statistics": {
            "unique_macs": len(mac_ports),
            "consistent_mac_port_identities": sum(1 for ports in mac_ports.values() if len(ports) == 1),
            "conflicting_macs": len(conflicting_macs),
            "conflicting_mac_addresses": conflicting_macs,
        },
    }
    evidence_digest = sha256_bytes(canonical_bytes(evidence_body))
    evidence = dict(evidence_body)
    evidence["evidence_set_digest"] = evidence_digest
    evidence["evidence_set_id"] = evidence_digest[:16]

    synthetic = deepcopy(latest["snapshot"])
    synthetic["snapshot_id"] = evidence["evidence_set_id"]
    synthetic["started_at"] = evidence["observation_span"]["started_at"]
    synthetic["completed_at"] = evidence["observation_span"]["completed_at"]
    synthetic["lifecycle"] = "COMPOSITE_EVIDENCE"
    synthetic["mac_observations"] = composite_observations

    vlan_mac_sets = defaultdict(set)
    for row in composite_observations:
        vlan_id = (row.get("vlan") or {}).get("vlan_id")
        if vlan_id is not None and row.get("mac"):
            vlan_mac_sets[int(vlan_id)].add(str(row["mac"]))
    for vlan in synthetic.get("vlans", []):
        vlan_id = vlan.get("vlan_id")
        count = len(vlan_mac_sets.get(int(vlan_id), set())) if vlan_id is not None else 0
        vlan["observed_mac_count"] = count
        vlan["observed"] = count > 0

    history = {
        "catalog": endpoint_catalog,
        "catalog_digest": sha256_bytes(canonical_bytes(endpoint_catalog)),
        "supporting_snapshots": [
            {"snapshot_id": item["snapshot_id"], "collection_digest": item["collection_digest"]}
            for item in collection_refs
        ],
    }
    envelope = {
        "snapshot_id": evidence["evidence_set_id"],
        "snapshot_schema_version": synthetic["schema_version"],
        "snapshot_sha256": sha256_bytes(canonical_bytes(synthetic)),
        "collection_digest": evidence_digest,
    }
    return {
        "evidence": evidence,
        "snapshot": synthetic,
        "envelope": envelope,
        "history": history,
        "findings": findings,
        "eligible": eligible,
        "latest": latest,
    }
