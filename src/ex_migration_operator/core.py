from __future__ import annotations

from pathlib import Path

from ex_migration_analyzer.core import read_json, sha256_file
from ex_migration_discovery.normalize import normalize_mac
from ex_migration_planner.cli import accepted_analyses
from ex_migration_provisioner import cli_base as provisioner_base
from ex_migration_provisioner.endpoint_stage import committed_endpoint_state
from ex_migration_provisioner.old_recovery import choose_recovery_transaction
from ex_migration_provisioner.precutover_probe import (
    analysis_for_approved_plan,
    silent_candidates,
)


class OperatorError(RuntimeError):
    pass


def _require(condition, message):
    if not condition:
        raise OperatorError(message)


def migration_root(settings, migration_id):
    return Path(settings["snapshot_root"]) / "migrations" / migration_id


def collection_paths(root):
    base = Path(root) / "old-switch" / "collections"
    if not base.is_dir():
        return []
    return sorted(
        path for path in base.glob("*/snapshot.json")
        if "_pending_" not in str(path.parent.name)
    )


def source_address_from_evidence(root):
    for path in reversed(collection_paths(root)):
        try:
            snapshot = read_json(path)
        except Exception:
            continue
        value = str(snapshot.get("management", {}).get("connection_address") or "").strip()
        if value:
            return value
    manifest = Path(root) / "manifest.json"
    if manifest.is_file():
        try:
            value = read_json(manifest)
            old_switch = value.get("old_switch", {})
            address = str(
                old_switch.get("connection_address")
                or old_switch.get("management_address")
                or ""
            ).strip()
            if address:
                return address
        except Exception:
            pass
    return None


def _vlan_names(analysis):
    values = {}
    for item in analysis.get("template_variables", {}).get("configured_vlans", []):
        vlan_id = item.get("vlan_id")
        name = str(item.get("name") or "")
        if vlan_id is not None and name:
            values[int(vlan_id)] = name
    return values


def historical_mac_lookup(root, value):
    mac = normalize_mac(str(value))
    selected_plan = provisioner_base.choose_approved_plan(Path(root))
    analysis, analysis_path, analysis_digest = analysis_for_approved_plan(
        Path(root), selected_plan
    )
    vlan_names = _vlan_names(analysis)
    ports = {
        str(item.get("interface") or ""): item
        for item in analysis.get("ports", [])
        if item.get("interface")
    }

    matches = []
    catalog = analysis.get("historical_evidence", {}).get("catalog", [])
    for item in catalog:
        try:
            item_mac = normalize_mac(str(item.get("mac") or ""))
        except ValueError:
            continue
        if item_mac != mac:
            continue
        interface = str(item.get("interface") or "")
        port = ports.get(interface, {})
        observed_vlan = item.get("vlan_id")
        configured_vlan = port.get("configured_data_vlan_id")
        matches.append({
            "interface": interface,
            "description": port.get("description"),
            "configured_data_vlan_id": configured_vlan,
            "configured_data_vlan_name": (
                vlan_names.get(int(configured_vlan))
                if configured_vlan is not None
                else None
            ),
            "observed_vlan_id": observed_vlan,
            "observed_vlan_name": (
                vlan_names.get(int(observed_vlan))
                if observed_vlan is not None
                else None
            ),
            "snapshot_ids": sorted(set(item.get("snapshot_ids") or [])),
        })

    if not matches:
        for interface, port in ports.items():
            identities = set()
            for item in port.get("historical_observations", []):
                try:
                    identities.add(normalize_mac(str(item.get("mac") or "")))
                except ValueError:
                    pass
            for item_mac in port.get("unique_macs", []):
                try:
                    identities.add(normalize_mac(str(item_mac)))
                except ValueError:
                    pass
            if mac not in identities:
                continue
            configured_vlan = port.get("configured_data_vlan_id")
            for observed_vlan in port.get("observed_data_vlan_ids", []) or [None]:
                matches.append({
                    "interface": interface,
                    "description": port.get("description"),
                    "configured_data_vlan_id": configured_vlan,
                    "configured_data_vlan_name": (
                        vlan_names.get(int(configured_vlan))
                        if configured_vlan is not None
                        else None
                    ),
                    "observed_vlan_id": observed_vlan,
                    "observed_vlan_name": (
                        vlan_names.get(int(observed_vlan))
                        if observed_vlan is not None
                        else None
                    ),
                    "snapshot_ids": [],
                })

    by_key = {}
    for item in matches:
        key = (item["interface"], item["observed_vlan_id"])
        if key not in by_key:
            by_key[key] = dict(item)
        else:
            by_key[key]["snapshot_ids"] = sorted(
                set(by_key[key]["snapshot_ids"]) | set(item["snapshot_ids"])
            )
    matches = sorted(
        by_key.values(),
        key=lambda item: (item["interface"], item["observed_vlan_id"] or -1),
    )
    interfaces = sorted(set(item["interface"] for item in matches))
    return {
        "migration_id": Path(root).name,
        "mac": mac,
        "approved_plan_id": selected_plan["plan"].get("plan_id"),
        "analysis_id": analysis.get("analysis_id"),
        "analysis_digest": analysis_digest,
        "analysis_path": str(analysis_path),
        "matches": matches,
        "port_consistency": (
            "NOT_FOUND" if not matches
            else "CONSISTENT" if len(interfaces) == 1
            else "CONFLICTING_HISTORY"
        ),
    }


def _valid_jsons(root, pattern, result_field=None, result_value=None):
    values = []
    for path in sorted(Path(root).glob(pattern)):
        try:
            value = read_json(path)
            integrity_path = path.parent / "integrity.json"
            if integrity_path.is_file():
                integrity = read_json(integrity_path)
                expected = integrity.get(path.name)
                if expected and expected != sha256_file(path):
                    continue
            if value.get("migration_id") not in (None, Path(root).name):
                continue
            if result_field and value.get(result_field) != result_value:
                continue
            values.append((path, value))
        except Exception:
            continue
    return values


def _successful_pre_stage(root):
    for _path, value in _valid_jsons(root, "transactions/*/transaction.json"):
        if value.get("phase") != "pre_stage":
            continue
        commit = value.get("commit", {})
        if (
            commit.get("status") == "COMMITTED_AND_CONFIRMED"
            and commit.get("confirmed") is True
            and value.get("validation", {}).get("result") == "PASS"
        ):
            return True
    return False


def _successful_qfx(root, approved_plan_digest):
    for _path, tx in _valid_jsons(root, "qfx-transactions/*/transaction.json"):
        if tx.get("status") != "COMMITTED_AND_CONFIRMED":
            continue
        if tx.get("validation", {}).get("result") != "PASS":
            continue
        qfx_plan_id = str(tx.get("qfx_plan_id") or "")
        plan_path = Path(root) / "qfx-vlan-plans" / qfx_plan_id / "plan.json"
        if not plan_path.is_file():
            continue
        try:
            plan = read_json(plan_path)
        except Exception:
            continue
        if plan.get("inputs", {}).get("migration_plan_digest") == approved_plan_digest:
            return True
    return False


def _successful_cleanup(root, approved_plan_digest):
    for _path, tx in _valid_jsons(
        root, "recovery-cleanup-transactions/*/transaction.json"
    ):
        if tx.get("status") != "COMMITTED_AND_CONFIRMED":
            continue
        if tx.get("validation", {}).get("result") != "PASS":
            continue
        inputs = tx.get("inputs", {})
        if inputs.get("approved_plan_digest") == approved_plan_digest:
            return True
    return False


def _probe_status(root, selected_plan):
    analysis, _path, analysis_digest = analysis_for_approved_plan(
        Path(root), selected_plan
    )
    candidates = silent_candidates(analysis)
    if not candidates:
        return {
            "status": "NOT_REQUIRED",
            "candidate_count": 0,
            "new_client_evidence_found": False,
        }
    plan_digest = selected_plan["plan_digest"]
    records = []
    for path, value in _valid_jsons(root, "old-switch/precutover-probes/*/probe.json"):
        inputs = value.get("inputs", {})
        if (
            inputs.get("approved_plan_digest") == plan_digest
            and inputs.get("analysis_digest") == analysis_digest
            and value.get("result") == "PASS"
        ):
            records.append((path, value))
    if not records:
        return {
            "status": "REQUIRED",
            "candidate_count": len(candidates),
            "new_client_evidence_found": False,
        }
    latest = records[-1][1]
    if latest.get("new_client_evidence_found"):
        return {
            "status": "HOLD_NEW_EVIDENCE",
            "candidate_count": len(candidates),
            "new_client_evidence_found": True,
        }
    return {
        "status": "PASS",
        "candidate_count": len(candidates),
        "new_client_evidence_found": False,
    }


def workflow_status(root):
    root = Path(root)
    collections = collection_paths(root)
    analyses = accepted_analyses(root)
    approved_plans = provisioner_base.approved_plan_candidates(root)
    selected_plan = approved_plans[0] if approved_plans else None

    status = {
        "migration_id": root.name,
        "collections": len(collections),
        "analysis": "COMPLETE" if analyses else "PENDING",
        "plan": "APPROVED" if selected_plan else "PENDING",
        "package": "PENDING",
        "render": "PENDING",
        "identity": "PENDING",
        "ex4400_prestage": "PENDING",
        "old_recovery": "PENDING",
        "silent_probe": {"status": "PENDING", "candidate_count": None},
        "physical_cutover": "PENDING",
        "qfx_attachment": "PENDING",
        "qfx_stage": "PENDING",
        "endpoints": "PENDING",
        "port_state": "PENDING",
        "cabling_report": "PENDING",
        "cleanup": "PENDING",
        "next_action": "discover",
    }
    if not collections:
        return status
    if not analyses:
        status["next_action"] = "analyze"
        return status
    if not selected_plan:
        status["next_action"] = "build"
        return status

    plan_digest = selected_plan["plan_digest"]
    packages = [
        item for item in provisioner_base.package_candidates(root)
        if item["package"].get("inputs", {}).get("plan_digest") == plan_digest
    ]
    if packages:
        status["package"] = "COMPLETE"
    renders = []
    for item in provisioner_base.render_candidates(root):
        try:
            package = provisioner_base.choose_package(root, item["manifest"].get("package_id"))
        except Exception:
            continue
        if package["package"].get("inputs", {}).get("plan_digest") == plan_digest:
            renders.append(item)
    if renders:
        status["render"] = "COMPLETE"
    if provisioner_base.identity_candidates(root):
        status["identity"] = "COMPLETE"
    if _successful_pre_stage(root):
        status["ex4400_prestage"] = "COMPLETE"
    try:
        choose_recovery_transaction(root)
        status["old_recovery"] = "COMPLETE"
    except Exception:
        pass

    if not all(
        status[name] == "COMPLETE"
        for name in ("package", "render", "identity", "ex4400_prestage", "old_recovery")
    ):
        status["next_action"] = "prestage"
        return status

    try:
        status["silent_probe"] = _probe_status(root, selected_plan)
    except Exception:
        status["silent_probe"] = {"status": "ERROR", "candidate_count": None}
    if status["silent_probe"]["status"] == "HOLD_NEW_EVIDENCE":
        status["next_action"] = "analyze"
        return status
    if status["silent_probe"]["status"] == "REQUIRED":
        status["next_action"] = "cutover-ready"
        return status

    attachments = []
    for path, value in _valid_jsons(root, "qfx-attachments/*/attachment.json"):
        if (
            value.get("result") == "PASS"
            and value.get("plan", {}).get("plan_digest") == plan_digest
        ):
            attachments.append((path, value))
    ack = root / "operator" / "physical-cutover.json"
    if attachments:
        status["physical_cutover"] = "INFERRED_COMPLETE"
        status["qfx_attachment"] = "COMPLETE"
    elif ack.is_file():
        try:
            value = read_json(ack)
            if value.get("approved_plan_digest") == plan_digest:
                status["physical_cutover"] = "ACKNOWLEDGED"
        except Exception:
            pass
    if status["physical_cutover"] == "PENDING":
        status["next_action"] = "cutover"
        return status

    if not attachments:
        status["next_action"] = "activate"
        return status
    if _successful_qfx(root, plan_digest):
        status["qfx_stage"] = "COMPLETE"
    else:
        status["next_action"] = "activate"
        return status

    try:
        completed = committed_endpoint_state(root, plan_digest)
        required = [
            item for item in selected_plan["plan"].get("port_intents", [])
            if item.get("planned_action") == "CORRELATE_AFTER_CABLE_MOVE"
        ]
        status["endpoints"] = "%d/%d" % (len(completed["completed"]), len(required))
        if len(completed["completed"]) < len(required):
            status["next_action"] = "activate"
            return status
        status["endpoints"] = "COMPLETE"
    except Exception:
        status["next_action"] = "activate"
        return status

    if _valid_jsons(root, "port-state-comparisons/*/comparison.json"):
        status["port_state"] = "COMPLETE"
    if _valid_jsons(root, "cabling-reports/*/report.json") or _valid_jsons(
        root, "cabling-reports/*/cabling-report.json"
    ):
        status["cabling_report"] = "COMPLETE"
    if status["port_state"] != "COMPLETE" or status["cabling_report"] != "COMPLETE":
        status["next_action"] = "validate"
        return status

    if _successful_cleanup(root, plan_digest):
        status["cleanup"] = "COMPLETE"
        status["next_action"] = "complete"
    else:
        status["next_action"] = "finalize"
    return status
