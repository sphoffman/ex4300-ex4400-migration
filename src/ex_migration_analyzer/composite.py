from __future__ import annotations

from copy import deepcopy
from collections import defaultdict

from .core import AnalysisError, canonical_bytes, sha256_bytes


def _sorted_dicts(values):
    return sorted((deepcopy(value) for value in values or []), key=lambda value: canonical_bytes(value))


def _device_state(snapshot):
    """Return the logical old-switch identity used across discovery collections.

    The migration tracks a logical closet switch.  VC mastership can change the
    top-level PyEZ serial and observed fact hostname behavior can vary by
    platform, so the configured hostname is the canonical identity invariant.
    """
    device = snapshot.get("device", {})
    return {
        "configured_hostname": device.get("configured_hostname") or device.get("hostname"),
    }


def _device_model_state(snapshot):
    device = snapshot.get("device", {})
    return {"model": device.get("model")}


def _device_serial_state(snapshot):
    device = snapshot.get("device", {})
    return {"serial_numbers": sorted(device.get("serial_numbers") or [])}


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


def _port_state_summary(candidates):
    """Return compact per-port discovery state without making it configuration authority.

    Real discovery candidates have collection paths, so reuse the same raw-sample
    reconstruction used by the post-cutover diagnostic.  Lightweight unit-test
    candidates may omit paths; in that case summarize only each snapshot's latest
    normalized interface state so composite tests remain independent of filesystem
    fixtures.
    """
    from ex_migration_provisioner.port_state import build_port_state_evidence, classify_port_state

    if all(candidate.get("path") for candidate in candidates):
        evidence = build_port_state_evidence(candidates)
        return {
            "schema_version": "1.0",
            "source": "RECONSTRUCTED_SAMPLE_ARTIFACTS",
            "total_sample_runs": evidence.get("total_sample_runs", 0),
            "ports": [
                {
                    "interface": row["interface"],
                    "samples": row["samples"],
                    "counts": row["counts"],
                    "stable_state": row["stable_state"],
                    "latest_state": row["latest_state"],
                    "latest_admin_status": row["latest_admin_status"],
                    "latest_oper_status": row["latest_oper_status"],
                    "first_observed_at": row["first_observed_at"],
                    "latest_observed_at": row["latest_observed_at"],
                }
                for row in evidence.get("ports", [])
            ],
        }

    samples = defaultdict(list)
    for candidate in candidates:
        snapshot = candidate["snapshot"]
        dynamic_ports = {
            str(row.get("physical_interface"))
            for row in snapshot.get("mac_observations", [])
            if row.get("physical_interface")
        }
        for item in snapshot.get("interfaces", []):
            interface = str(item.get("physical_name") or "")
            if not interface or item.get("effective_mode") != "access" or item.get("ae_parent"):
                continue
            state = classify_port_state(
                item.get("admin_status"),
                item.get("oper_status"),
                interface in dynamic_ports,
            )
            samples[interface].append({
                "state": state,
                "admin_status": item.get("admin_status"),
                "oper_status": item.get("oper_status"),
                "observed_at": snapshot.get("completed_at"),
            })
    ports = []
    states = ("ACTIVE_MAC", "UP_SILENT", "LINK_DOWN", "ADMIN_DOWN", "NOT_OBSERVED")
    for interface in sorted(samples):
        rows = samples[interface]
        counts = {state: sum(1 for row in rows if row["state"] == state) for state in states}
        non_missing = {row["state"] for row in rows if row["state"] != "NOT_OBSERVED"}
        latest = rows[-1]
        ports.append({
            "interface": interface,
            "samples": len(rows),
            "counts": counts,
            "stable_state": next(iter(non_missing)) if len(non_missing) == 1 else "VARIABLE",
            "latest_state": latest["state"],
            "latest_admin_status": latest["admin_status"],
            "latest_oper_status": latest["oper_status"],
            "first_observed_at": rows[0]["observed_at"],
            "latest_observed_at": latest["observed_at"],
        })
    return {
        "schema_version": "1.0",
        "source": "SNAPSHOT_LATEST_FALLBACK",
        "total_sample_runs": sum(len(rows) for rows in samples.values()),
        "ports": ports,
    }


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
            "configured old-switch hostname changed across eligible discovery collections",
            device_variants,
        ))

    model_variants = _variants(eligible, _device_model_state)
    consistency["device_model"] = "CONSISTENT" if len(model_variants) == 1 else "CHANGED"
    if len(model_variants) > 1:
        findings.append(_finding(
            "REVIEW", "DEVICE_MODEL_CHANGED", "device-model",
            "reported device model changed across eligible discovery collections; latest eligible model is used as current platform state",
            model_variants,
        ))

    serial_variants = _variants(eligible, _device_serial_state)
    consistency["device_serial_observation"] = "CONSISTENT" if len(serial_variants) == 1 else "CHANGED"

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

    port_state_summary = _port_state_summary(eligible)
    for row in port_state_summary.get("ports", []):
        state = row.get("latest_state")
        if state not in ("UP_SILENT", "LINK_DOWN", "ADMIN_DOWN"):
            continue
        count = int((row.get("counts") or {}).get(state, 0))
        total = int(row.get("samples", 0))
        descriptions = {
            "UP_SILENT": "access port was operationally up with no dynamic MAC in the latest approved discovery sample",
            "LINK_DOWN": "access port link was down in the latest approved discovery sample",
            "ADMIN_DOWN": "access port was administratively down in the latest approved discovery sample",
        }
        findings.append(_finding(
            "INFO",
            "PORT_STATE_%s" % state,
            row["interface"],
            "%s (%d/%d reconstructed samples in this state)" % (descriptions[state], count, total),
            [{
                "stable_state": row.get("stable_state"),
                "counts": row.get("counts"),
                "first_observed_at": row.get("first_observed_at"),
                "latest_observed_at": row.get("latest_observed_at"),
            }],
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
        "port_state_summary": port_state_summary,
        "hardware_observations": {
            "model_variants": model_variants,
            "serial_variants": serial_variants,
        },
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
