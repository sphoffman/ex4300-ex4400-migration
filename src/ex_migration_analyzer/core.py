from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


class AnalysisError(RuntimeError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AnalysisError("cannot read JSON %s: %s" % (path, exc))


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(str(temporary), str(path))


def safe_artifact(collection, relative):
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts or not candidate.parts:
        raise AnalysisError("unsafe artifact path: %r" % relative)
    resolved_root = collection.resolve()
    unresolved = collection / candidate
    if unresolved.is_symlink():
        raise AnalysisError("symlinked artifact is not allowed: %r" % relative)
    current = collection
    for part in candidate.parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise AnalysisError("symlinked artifact parent is not allowed: %r" % relative)
    resolved = unresolved.resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        raise AnalysisError("artifact escapes collection: %r" % relative)
    return resolved


def validate_collection(collection):
    collection = Path(collection)
    snapshot_path = collection / "snapshot.json"
    integrity_path = collection / "integrity.json"
    errors_path = collection / "errors.json"
    for required in (snapshot_path, integrity_path, errors_path):
        if not required.is_file() or required.is_symlink():
            raise AnalysisError("missing or unsafe required file: %s" % required)
    snapshot = read_json(snapshot_path)
    if snapshot.get("schema_version") not in ("1.2", "1.3", "1.4"):
        raise AnalysisError("unsupported snapshot schema %r" % snapshot.get("schema_version"))
    required_keys = (
        "snapshot_id", "migration_id", "device_role", "started_at", "completed_at",
        "device", "management", "collection_policy", "capabilities", "interfaces",
        "vlans", "voice_policy", "mac_observations", "raw_artifacts", "errors",
    )
    missing = [key for key in required_keys if key not in snapshot]
    if missing:
        raise AnalysisError("snapshot is missing required fields: %s" % ", ".join(missing))
    if snapshot["device_role"] != "old-switch":
        raise AnalysisError("snapshot device_role must be old-switch")

    legacy_integrity = read_json(integrity_path)
    for name, expected in legacy_integrity.items():
        path = safe_artifact(collection, name)
        if not path.is_file() or sha256_file(path) != expected:
            raise AnalysisError("top-level integrity failure: %s" % name)

    declared = set()
    members = []
    for artifact in snapshot["raw_artifacts"]:
        relative = artifact.get("path")
        expected = artifact.get("sha256")
        if not isinstance(relative, str) or not re.fullmatch(r"[0-9a-f]{64}", str(expected)):
            raise AnalysisError("malformed raw artifact declaration")
        if relative in declared:
            raise AnalysisError("duplicate raw artifact declaration: %s" % relative)
        declared.add(relative)
        path = safe_artifact(collection, relative)
        if not path.is_file():
            raise AnalysisError("missing raw artifact: %s" % relative)
        actual = sha256_file(path)
        if actual != expected:
            raise AnalysisError("raw artifact integrity failure: %s" % relative)
        members.append({"path": relative, "sha256": actual})

    actual_raw = {
        str(path.relative_to(collection))
        for path in (collection / "raw").rglob("*")
        if path.is_file()
    }
    undeclared = sorted(actual_raw - declared)
    if undeclared:
        raise AnalysisError("undeclared raw artifacts: %s" % ", ".join(undeclared))

    envelope = {
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_schema_version": snapshot["schema_version"],
        "snapshot_sha256": sha256_file(snapshot_path),
        "errors_sha256": sha256_file(errors_path),
        "raw_artifacts": sorted(members, key=lambda item: item["path"]),
    }
    envelope["collection_digest"] = sha256_bytes(canonical_bytes(envelope))
    return snapshot, envelope


def evaluate_policy(snapshot, policy):
    blockers = []
    reviews = []
    accepted = policy.get("accepted_snapshot_schemas", [])
    if snapshot["schema_version"] not in accepted:
        blockers.append(("SNAPSHOT_SCHEMA_NOT_ACCEPTED", "snapshot schema is not accepted by policy"))
        return blockers, reviews
    observation = policy.get("observation", {})
    samples = int(snapshot.get("collection_policy", {}).get("samples", 0))
    duration = int(snapshot.get("collection_policy", {}).get("duration_seconds", 0))
    sample_runs = snapshot.get("sample_runs")
    required_commands = policy.get("required_capabilities", [])
    if snapshot["schema_version"] in ("1.3", "1.4"):
        if not isinstance(sample_runs, list) or len(sample_runs) != samples:
            blockers.append(("SAMPLE_LEDGER_INVALID", "sample ledger does not match the declared sample count"))
            successful_samples = 0
        else:
            successful_samples = sum(
                1 for run in sample_runs
                if all(
                    next((entry.get("status") for entry in run.get("commands", []) if entry.get("command") == command), None) == "SUCCESS"
                    for command in required_commands
                )
            )
        if snapshot["schema_version"] == "1.4":
            reconciliation = snapshot.get("collection_policy", {}).get("mac_table_reconciliation")
            if not isinstance(reconciliation, list) or len(reconciliation) != samples:
                blockers.append(("MAC_RECONCILIATION_INVALID", "MAC-table reconciliation ledger does not match the declared sample count"))
                successful_samples = 0
            elif any(item.get("status") != "RECONCILED" for item in reconciliation):
                blockers.append(("MAC_RECONCILIATION_FAILED", "one or more MAC-table samples could not be reconciled"))
    else:
        successful_samples = samples
    if successful_samples < int(observation.get("minimum_samples", 1)):
        blockers.append(("INSUFFICIENT_SAMPLES", "observation sample minimum was not met"))
    if duration < int(observation.get("minimum_duration_seconds", 0)):
        blockers.append(("INSUFFICIENT_DURATION", "observation duration minimum was not met"))
    for command in policy.get("required_capabilities", []):
        value = snapshot.get("capabilities", {}).get(command, "missing")
        if value not in ("xml_and_text", "text_only", "xml_only"):
            blockers.append(("REQUIRED_CAPABILITY_UNAVAILABLE", "%s: %s" % (command, value)))
    if snapshot.get("management", {}).get("consistency") != "CONSISTENT":
        blockers.append(("MANAGEMENT_IDENTITY_INCONSISTENT", "management profile is not consistent"))
    if not snapshot.get("voice_policy", {}).get("valid"):
        reviews.append(("VOICE_POLICY_NOT_VALIDATED", "voice policy was not validated"))
    vc = snapshot.get("virtual_chassis", {}).get("status")
    if vc == "unsupported":
        target = blockers if policy.get("require_virtual_chassis") else reviews
        target.append(("VIRTUAL_CHASSIS_UNSUPPORTED", "platform did not support VC validation"))
    return blockers, reviews


def _interface_map(snapshot):
    return {item["physical_name"]: item for item in snapshot["interfaces"]}


def correlate(snapshot, policy):
    interfaces = _interface_map(snapshot)
    voice_id = snapshot.get("voice_policy", {}).get("vlan_id")
    observations = defaultdict(list)
    excluded = []
    for item in snapshot["mac_observations"]:
        port = item["physical_interface"]
        state = interfaces.get(port, {})
        confirmed_access = (
            item.get("interface_class") == "physical_access"
            and not state.get("ae_parent")
            and state.get("effective_mode") == "access"
        )
        if not confirmed_access:
            excluded.append({
                "mac": item["mac"], "vlan_id": item.get("vlan", {}).get("vlan_id"),
                "physical_interface": port, "reason": "INFRASTRUCTURE_OR_UNRESOLVED",
            })
            continue
        observations[port].append(item)

    mac_ports = defaultdict(set)
    for port, items in observations.items():
        for item in items:
            mac_ports[item["mac"]].add(port)

    ports = []
    findings = []
    access_names = sorted(
        name for name, state in interfaces.items()
        if state.get("effective_mode") == "access" and not state.get("ae_parent")
    )
    for port in access_names:
        state = interfaces[port]
        items = observations.get(port, [])
        unique_macs = sorted({item["mac"] for item in items})
        voice_macs = sorted({item["mac"] for item in items if item.get("vlan", {}).get("vlan_id") == voice_id})
        data_macs = sorted({item["mac"] for item in items if item.get("vlan", {}).get("vlan_id") != voice_id})
        observed_data_vlans = sorted({
            item.get("vlan", {}).get("vlan_id") for item in items
            if item.get("vlan", {}).get("vlan_id") != voice_id
        })
        configured = (state.get("untagged_vlan") or {}).get("vlan_id")
        moved = sorted(mac for mac in unique_macs if len(mac_ports[mac]) > 1)
        port_findings = []
        if moved:
            port_findings.append("MAC_MULTI_PORT")
            findings.append(_finding("REVIEW", "MAC_MULTI_PORT", port, "MAC observed on multiple access ports", moved))
        if len(observed_data_vlans) > 1:
            if configured is None:
                port_findings.append("DATA_VLAN_UNRESOLVED")
                findings.append(_finding("REVIEW", "DATA_VLAN_UNRESOLVED", port, "multiple data VLANs without an authoritative static VLAN", observed_data_vlans))
            elif configured not in observed_data_vlans:
                port_findings.append("OBSERVED_CONFIGURED_VLAN_CONFLICT")
                findings.append(_finding("REVIEW", "OBSERVED_CONFIGURED_VLAN_CONFLICT", port, "observed VLANs conflict with configured access VLAN", observed_data_vlans))
        if not unique_macs and configured is None and state.get("oper_status") == "down":
            disposition = "UNUSED_ACCESS_PORT"
        elif not unique_macs and configured is None:
            disposition = "ACTIVE_UNASSIGNED_SILENT"
            findings.append(_finding("REVIEW", "ACTIVE_UNASSIGNED_SILENT", port, "operational access port had no configured data VLAN and no observed MAC", []))
        elif not unique_macs:
            disposition = "CONFIGURED_NO_MAC"
            findings.append(_finding("REVIEW", "CONFIGURED_NO_MAC", port, "configured access port had no observed MAC", []))
        elif moved or "DATA_VLAN_UNRESOLVED" in port_findings:
            disposition = "CORRELATION_BLOCKED"
        elif voice_macs and data_macs:
            disposition = "PHONE_PLUS_PC"
        elif voice_macs:
            disposition = "PHONE_ONLY"
        elif len(data_macs) > 1:
            disposition = "MULTIPLE_DATA_MACS"
        else:
            disposition = "DATA_ONLY"
        ports.append({
            "interface": port,
            "description": state.get("description"),
            "configured_data_vlan_id": configured,
            "observed_data_vlan_ids": observed_data_vlans,
            "unique_macs": unique_macs,
            "data_macs": data_macs,
            "voice_macs": voice_macs,
            "disposition": disposition,
            "finding_codes": sorted(port_findings),
        })
    return ports, sorted(excluded, key=lambda item: (item["physical_interface"], item["vlan_id"] or -1, item["mac"])), findings


def _finding(severity, code, subject, message, evidence):
    return {"severity": severity, "code": code, "subject": subject, "message": message, "evidence": evidence}


def analyze(snapshot, envelope, policy, policy_digest, approval_digest, analyzer_version, history=None):
    blockers, reviews = evaluate_policy(snapshot, policy)
    ports, excluded, correlation_findings = correlate(snapshot, policy)
    findings = [_finding("BLOCKER", code, "snapshot", message, []) for code, message in blockers]
    findings += [_finding("REVIEW", code, "snapshot", message, []) for code, message in reviews]
    findings += correlation_findings
    findings = sorted(findings, key=lambda item: (item["severity"], item["code"], item["subject"]))
    result = "BLOCKED" if blockers else "REVIEW_REQUIRED" if any(f["severity"] == "REVIEW" for f in findings) else "READY"
    key = {
        "collection_digest": envelope["collection_digest"],
        "approval_digest": approval_digest,
        "policy_digest": policy_digest,
        "analyzer_version": analyzer_version,
    }
    if history:
        key["historical_evidence_catalog_digest"] = history["catalog_digest"]
    analysis_id = sha256_bytes(canonical_bytes(key))[:16]
    management = snapshot["management"]
    template_variables = {
        "migration_id": snapshot["migration_id"],
        "old_hostname": snapshot["device"].get("hostname"),
        "new_hostname": snapshot["device"].get("proposed_hostname"),
        "management_vlan_id": management.get("vlan_id"),
        "management_vlan_name": management.get("vlan_name"),
        "management_interface": management.get("l3_interface"),
        "management_ip": management.get("production_ipv4"),
        "management_prefix": management.get("addresses", [None])[0] if management.get("addresses") else None,
        "management_gateway": management.get("default_gateway"),
        "snmp_location": management.get("snmp", {}).get("location"),
        "snmp_engine_id": management.get("snmp", {}).get("engine_id"),
        "configured_vlans": sorted(snapshot["vlans"], key=lambda item: (item.get("vlan_id") is None, item.get("vlan_id") or 0, item["name"])),
    }
    if history:
        by_port = defaultdict(list)
        for item in history["catalog"]:
            by_port[item["interface"]].append(item)
        for port in ports:
            historical = sorted(by_port.get(port["interface"], []), key=lambda item: (item["mac"], item["vlan_id"]))
            port["historical_observations"] = historical
            if port["unique_macs"]:
                port["observation_history"] = "OBSERVED_IN_BASELINE"
            elif historical:
                port["observation_history"] = "HISTORICALLY_OBSERVED"
            else:
                port["observation_history"] = "NEVER_OBSERVED"
    result = {
        "schema_version": "1.0", "analysis_id": analysis_id, "result": result,
        "inputs": dict(key, snapshot_id=snapshot["snapshot_id"], snapshot_schema_version=snapshot["schema_version"]),
        "template_variables": template_variables, "ports": ports,
        "excluded_observations": excluded, "findings": findings,
        "statistics": {
            "ports": len(ports), "raw_mac_observations": len(snapshot["mac_observations"]),
            "excluded_observations": len(excluded),
            "unique_endpoint_macs": len({m for port in ports for m in port["unique_macs"]}),
        },
    }
    if history:
        result["historical_evidence"] = history
    return result


def render_report(analysis):
    lines = [
        "# Migration analysis: %s" % analysis["template_variables"]["migration_id"], "",
        "- Analysis: `%s`" % analysis["analysis_id"],
        "- Result: **%s**" % analysis["result"],
        "- Snapshot: `%s`" % analysis["inputs"]["snapshot_id"], "",
        "## Findings", "",
    ]
    if analysis["findings"]:
        lines.extend("- **%s / %s** `%s`: %s" % (f["severity"], f["code"], f["subject"], f["message"]) for f in analysis["findings"])
    else:
        lines.append("- None")
    lines += ["", "## Access ports", "", "| Port | Configured VLAN | Observed VLANs | MACs | Disposition |", "|---|---:|---|---:|---|"]
    for port in analysis["ports"]:
        lines.append("| %s | %s | %s | %d | %s |" % (
            port["interface"], port["configured_data_vlan_id"] or "",
            ", ".join(str(value) for value in port["observed_data_vlan_ids"]),
            len(port["unique_macs"]), port["disposition"],
        ))
    return "\n".join(lines) + "\n"
