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
from ex_migration_provisioner import cli_base as provisioner_base
from ex_migration_provisioner.endpoint_stage import committed_endpoint_state

from .core import OperatorError


def _valid_correlations(root, approved_plan_digest):
    values = []
    base = Path(root) / "endpoint-correlations"
    for path in sorted(base.glob("*/correlation.json")):
        try:
            integrity = read_json(path.parent / "integrity.json")
            if integrity.get("correlation.json") != sha256_file(path):
                continue
            value = read_json(path)
            if value.get("migration_id") != Path(root).name:
                continue
            if value.get("inputs", {}).get("approved_plan_digest") != approved_plan_digest:
                continue
            values.append((path, value))
        except Exception:
            continue
    return values


def latest_correlation(root, approved_plan_digest):
    values = _valid_correlations(root, approved_plan_digest)
    if not values:
        return None
    return values[-1]


def required_endpoint_intents(plan):
    return [
        item for item in plan.get("port_intents", [])
        if item.get("planned_action") == "CORRELATE_AFTER_CABLE_MOVE"
    ]


def active_endpoint_exceptions(root, approved_plan_digest, completed_old_interfaces=None):
    completed = set(completed_old_interfaces or [])
    accepted = {}
    base = Path(root) / "operator" / "endpoint-exceptions"
    for path in sorted(base.glob("*/exception.json")):
        try:
            integrity = read_json(path.parent / "integrity.json")
            if integrity.get("exception.json") != sha256_file(path):
                continue
            value = read_json(path)
            if value.get("migration_id") != Path(root).name:
                continue
            if value.get("approved_plan_digest") != approved_plan_digest:
                continue
            if value.get("accepted") is not True:
                continue
            for item in value.get("unresolved", []):
                old_interface = str(item.get("old_interface") or "")
                if old_interface:
                    accepted[old_interface] = dict(item)
        except Exception:
            continue
    return {
        old_interface: item
        for old_interface, item in accepted.items()
        if old_interface not in completed
    }


def endpoint_progress(root, selected_plan):
    plan = selected_plan["plan"]
    plan_digest = selected_plan["plan_digest"]
    completed = committed_endpoint_state(Path(root), plan_digest)
    completed_old = set(completed["by_old"])
    required = required_endpoint_intents(plan)
    required_old = {
        str(item.get("old_interface") or "")
        for item in required
        if item.get("old_interface")
    }
    active = active_endpoint_exceptions(root, plan_digest, completed_old)
    accepted_old = set(active) & required_old
    unresolved = sorted(required_old - completed_old - accepted_old)
    return {
        "required": required,
        "required_count": len(required_old),
        "completed": completed,
        "completed_count": len(completed_old & required_old),
        "active_exceptions": active,
        "accepted_count": len(accepted_old),
        "unresolved": unresolved,
        "satisfied": not unresolved,
    }


def accept_latest_unresolved(root, reason):
    root = Path(root)
    reason = str(reason or "").strip()
    if not reason:
        raise OperatorError("endpoint exception reason must not be empty")

    selected_plan = provisioner_base.choose_approved_plan(root)
    plan_digest = selected_plan["plan_digest"]
    progress = endpoint_progress(root, selected_plan)
    if not progress["unresolved"]:
        raise OperatorError("there are no unresolved endpoint intents to accept")

    current = latest_correlation(root, plan_digest)
    if current is None:
        raise OperatorError("no current endpoint correlation exists; run activate first")
    correlation_path, correlation = current
    holds = {
        str(item.get("old_interface") or ""): dict(item)
        for item in correlation.get("correlation", {}).get("holds", [])
        if item.get("old_interface")
    }
    missing = [name for name in progress["unresolved"] if name not in holds]
    if missing:
        raise OperatorError(
            "latest endpoint correlation does not account for unresolved intent(s): %s"
            % ", ".join(missing)
        )

    unresolved = [holds[name] for name in progress["unresolved"]]
    accepted_at = utc_now()
    key = {
        "migration_id": root.name,
        "approved_plan_digest": plan_digest,
        "correlation_id": correlation.get("correlation_id"),
        "correlation_digest": sha256_file(correlation_path),
        "unresolved": unresolved,
        "operator_reason": reason,
        "accepted_at": accepted_at,
    }
    exception_id = sha256_bytes(canonical_bytes(key))[:16]
    value = {
        "schema_version": "1.0",
        "exception_id": exception_id,
        "migration_id": root.name,
        "approved_plan_id": selected_plan["plan"].get("plan_id"),
        "approved_plan_digest": plan_digest,
        "correlation_id": correlation.get("correlation_id"),
        "correlation_digest": sha256_file(correlation_path),
        "accepted_at": accepted_at,
        "accepted": True,
        "operator_reason": reason,
        "unresolved": unresolved,
        "safety": {
            "marks_endpoints_migrated": False,
            "authorizes_endpoint_configuration": False,
            "permits_workflow_to_continue": True,
            "later_reconciliation_allowed": True,
        },
    }
    destination = root / "operator" / "endpoint-exceptions" / exception_id
    destination.mkdir(parents=True, exist_ok=False)
    path = destination / "exception.json"
    atomic_json(path, value)
    atomic_json(destination / "integrity.json", {"exception.json": sha256_file(path)})
    return destination, value
