from __future__ import annotations

import re

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    sha256_bytes,
    sha256_file,
    utc_now,
)

from .core import ProvisioningError


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def transaction_id(qfx_plan, candidate_diffs):
    key = {
        "migration_id": qfx_plan["migration_id"],
        "qfx_plan_id": qfx_plan["qfx_plan_id"],
        "candidate_diffs": {
            role: sha256_bytes(candidate_diffs[role].encode("utf-8"))
            for role in sorted(candidate_diffs)
        },
    }
    return sha256_bytes(canonical_bytes(key))[:16]


def build_transaction(qfx_plan, candidate_diffs, approved_at, confirm_minutes):
    tx_id = transaction_id(qfx_plan, candidate_diffs)
    return {
        "schema_version": "1.0",
        "transaction_id": tx_id,
        "migration_id": qfx_plan["migration_id"],
        "qfx_plan_id": qfx_plan["qfx_plan_id"],
        "approved_at": approved_at,
        "confirm_minutes": int(confirm_minutes),
        "devices": [
            {
                "role": item["role"],
                "management_address": item["management_address"],
                "physical_interface": item["physical_interface"],
                "ae_interface": item["ae_interface"],
                "candidate_diff_sha256": sha256_bytes(
                    candidate_diffs[item["role"]].encode("utf-8")
                ),
                "commit_status": "NOT_STARTED",
            }
            for item in sorted(qfx_plan["devices"], key=lambda row: row["role"])
        ],
        "validation": {
            "result": "PENDING",
            "validated_at": None,
            "devices": [],
        },
        "status": "APPROVED_PENDING_COMMIT",
        "safety": {
            "coordinated_dual_qfx": True,
            "commit_confirmed_required": True,
            "final_confirmation_requires_both_valid": True,
            "rollback_both_on_failure": True,
            "ex4400_writes_authorized": False,
        },
    }


def persist_transaction(migration_root, transaction, candidate_diffs):
    directory = migration_root / "qfx-transactions" / transaction["transaction_id"]
    directory.mkdir(parents=True, exist_ok=True)
    paths = {}
    for role, text in candidate_diffs.items():
        path = directory / ("%s.diff" % role)
        normalized = str(text or "")
        if normalized and not normalized.endswith("\n"):
            normalized += "\n"
        if path.exists():
            _require(
                path.read_text(encoding="utf-8") == normalized,
                "QFX transaction candidate diff changed unexpectedly for %s" % role,
            )
        else:
            path.write_text(normalized, encoding="utf-8")
        paths[path.name] = sha256_file(path)

    tx_path = directory / "transaction.json"
    atomic_json(tx_path, transaction)
    paths["transaction.json"] = sha256_file(tx_path)
    atomic_json(directory / "integrity.json", paths)
    return directory


def _target_lldp_neighbors(text, expected_hostname):
    expected = str(expected_hostname).strip().lower()
    results = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.lower().startswith("local interface"):
            continue
        columns = re.split(r"\s{2,}", line)
        if len(columns) < 5:
            continue
        local_interface, parent_interface = columns[0], columns[1]
        remote_system_name = columns[-1].strip()
        if remote_system_name.lower() != expected:
            continue
        results.append({
            "local_interface": local_interface,
            "parent_interface": parent_interface,
            "remote_system_name": remote_system_name,
        })
    return results


def _planned_statements_satisfied(expected_statements, statement_set):
    for statement in expected_statements:
        if statement.startswith("set "):
            if statement not in statement_set:
                return False
        elif statement.startswith("delete "):
            if ("set " + statement[7:]) in statement_set:
                return False
        else:
            return False
    return True


def validate_post_commit_device(dev, plan_device, expected_ex_hostname):
    physical = plan_device["physical_interface"]
    ae = plan_device["ae_interface"]
    lldp_text = dev.cli("show lldp neighbors", warning=False) or ""
    neighbors = _target_lldp_neighbors(lldp_text, expected_ex_hostname)
    matching_local = [
        item for item in neighbors
        if str(item.get("local_interface") or "") == physical
    ]

    physical_config = dev.cli(
        "show configuration interfaces %s | display set" % physical,
        warning=False,
    ) or ""
    ae_config = dev.cli(
        "show configuration interfaces %s | display set" % ae,
        warning=False,
    ) or ""
    lacp_text = dev.cli(
        "show lacp interfaces %s extensive" % ae,
        warning=False,
    ) or ""

    expected_parent = "set interfaces %s ether-options 802.3ad %s" % (physical, ae)
    alternate_parent = "set interfaces %s gigether-options 802.3ad %s" % (physical, ae)
    expected_statements = list(plan_device.get("statements", []))
    statement_set = {line.strip() for line in ae_config.splitlines() if line.strip()}
    checks = {
        "lldp_target_on_bound_physical_interface": len(matching_local) == 1,
        "lldp_parent_matches_bound_ae": len(matching_local) == 1
        and str(matching_local[0].get("parent_interface") or "") == ae,
        "physical_interface_still_maps_to_bound_ae": (
            expected_parent in physical_config or alternate_parent in physical_config
        ),
        "all_planned_vlan_changes_present": _planned_statements_satisfied(
            expected_statements, statement_set
        ),
        "lacp_force_up_absent": (
            "set interfaces %s aggregated-ether-options lacp force-up" % ae
        ) not in statement_set,
        "lacp_collecting_distributing": (
            physical in lacp_text
            and "collecting" in lacp_text.lower()
            and "distributing" in lacp_text.lower()
        ),
    }
    return {
        "role": plan_device["role"],
        "physical_interface": physical,
        "ae_interface": ae,
        "checks": checks,
        "result": "PASS" if all(checks.values()) else "FAIL",
    }


def validate_post_commit_pair(devices, qfx_plan, expected_ex_hostname):
    _require(expected_ex_hostname, "expected EX hostname is required for QFX validation")
    results = []
    for item in sorted(qfx_plan["devices"], key=lambda row: row["role"]):
        _require(item["role"] in devices, "missing connected QFX role %s" % item["role"])
        results.append(
            validate_post_commit_device(
                devices[item["role"]],
                item,
                expected_ex_hostname,
            )
        )
    passed = all(item["result"] == "PASS" for item in results)
    return {
        "result": "PASS" if passed else "FAIL",
        "validated_at": utc_now(),
        "devices": results,
    }
