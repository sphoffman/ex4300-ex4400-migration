from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ex_migration_provisioner import cli_base as provisioner_base

from . import cli as legacy
from . import core as operator_core
from .core import OperatorError, migration_root
from .endpoint_exceptions import accept_latest_unresolved, endpoint_progress


def workflow_status(root):
    """Current operator status with accepted endpoint exceptions as a continuation state."""
    root = Path(root)
    state = legacy.workflow_status(root)

    if state.get("qfx_stage") != "COMPLETE":
        return state

    try:
        selected_plan = provisioner_base.choose_approved_plan(root)
        progress = endpoint_progress(root, selected_plan)
    except Exception:
        return state

    required = progress["required_count"]
    completed = progress["completed_count"]
    accepted = progress["accepted_count"]

    if required == 0 or completed == required:
        state["endpoints"] = "COMPLETE"
    elif accepted:
        suffix = "ACCEPTED_EXCEPTION" if accepted == 1 else "ACCEPTED_EXCEPTIONS"
        state["endpoints"] = "%d/%d + %d %s" % (
            completed,
            required,
            accepted,
            suffix,
        )
    else:
        state["endpoints"] = "%d/%d" % (completed, required)

    if not progress["satisfied"]:
        state["next_action"] = "activate"
        return state

    plan_digest = selected_plan["plan_digest"]
    comparisons = [
        value for _path, value in operator_core._valid_jsons(
            root, "port-state-comparisons/*/comparison.json"
        )
        if value.get("approved_plan_digest") == plan_digest
    ]
    reports = [
        value for _path, value in operator_core._valid_jsons(
            root, "facilities-reports/*/report.json"
        )
        if value.get("source_approved_plan_digest") == plan_digest
    ]
    state["port_state"] = "COMPLETE" if comparisons else "PENDING"
    state["cabling_report"] = "COMPLETE" if reports else "PENDING"

    if state["port_state"] != "COMPLETE" or state["cabling_report"] != "COMPLETE":
        state["next_action"] = "validate"
        return state

    if operator_core._successful_cleanup(root, plan_digest):
        state["cleanup"] = "COMPLETE"
        state["next_action"] = "complete"
    else:
        state["next_action"] = "finalize"
    return state


def _print_unresolved(progress):
    print("\nUnresolved endpoint intents: %d" % len(progress["unresolved"]))
    by_old = {
        str(item.get("old_interface") or ""): item
        for item in progress["required"]
        if item.get("old_interface")
    }
    for old_interface in progress["unresolved"]:
        item = by_old.get(old_interface, {})
        print("  %s" % old_interface)
        if item.get("description"):
            print("    Description: %s" % item["description"])
        macs = item.get("endpoint_macs") or []
        if macs:
            print("    Expected MACs: %s" % ", ".join(str(value) for value in macs))
        vlan_id = item.get("configured_data_vlan_id")
        if vlan_id is not None:
            print("    Configured data VLAN: %s" % vlan_id)


def _offer_exception_acceptance(root):
    selected_plan = provisioner_base.choose_approved_plan(root)
    progress = endpoint_progress(root, selected_plan)
    if not progress["unresolved"]:
        if progress["accepted_count"]:
            print("\nAll previously accepted endpoint exceptions are now resolved by committed mappings.")
        return 0

    if progress["accepted_count"]:
        print(
            "\n%d unresolved endpoint intent(s) remain covered by accepted exception(s)."
            % progress["accepted_count"]
        )
        print("Run './migrate %s activate' later to retry reconciliation." % root.name)
        return 0

    _print_unresolved(progress)
    print("\nNo unresolved endpoint will be marked migrated or configured by accepting an exception.")
    answer = input(
        "Accept these unresolved endpoint intents as migration exceptions and continue? [y/N]: "
    ).strip().lower()
    if answer not in ("y", "yes"):
        print("Endpoint activation remains pending; rerun activate when more devices are visible.")
        return 0

    reason = input("Reason for accepting these unresolved endpoints: ").strip()
    if not reason:
        raise OperatorError("a reason is required to accept unresolved endpoint exceptions")
    confirm = input(
        "Record this exception without marking the endpoints migrated? [y/N]: "
    ).strip().lower()
    if confirm not in ("y", "yes"):
        print("Endpoint exception was not recorded.")
        return 0

    destination, value = accept_latest_unresolved(root, reason)
    print("\nEndpoint exception: %s (CREATED)" % value["exception_id"])
    print("  Accepted unresolved intents: %d" % len(value["unresolved"]))
    print("  Endpoints marked migrated: no")
    print("  Later activate reconciliation: allowed")
    print("  Record: %s" % (destination / "exception.json"))
    return 0


def _activate(migration_id, extra):
    result = legacy._activate(migration_id, extra)
    if result != 0:
        return result
    settings_parser = argparse.ArgumentParser(add_help=False)
    settings_parser.add_argument("--settings", default="config/site.json")
    args, _unknown = settings_parser.parse_known_args(extra)
    root = migration_root(legacy._settings(args.settings), migration_id)
    return _offer_exception_acceptance(root)


def _dispatch(migration_id, command, extra):
    if command == "status":
        settings_parser = argparse.ArgumentParser(add_help=False)
        settings_parser.add_argument("--settings", default="config/site.json")
        args, unknown = settings_parser.parse_known_args(extra)
        if unknown:
            raise OperatorError("unrecognized status arguments: %s" % " ".join(unknown))
        state = workflow_status(migration_root(legacy._settings(args.settings), migration_id))
        legacy._status_text(state)
        return 0
    if command == "activate":
        return _activate(migration_id, extra)
    return legacy._dispatch(migration_id, command, extra)


def _resume(migration_id):
    settings = legacy._settings("config/site.json")
    root = migration_root(settings, migration_id)
    state = workflow_status(root)
    legacy._status_text(state)
    action = state["next_action"]
    if action == "complete":
        print("\nMigration workflow is complete.")
        if "+" in str(state.get("endpoints") or ""):
            print("Accepted endpoint exceptions remain eligible for later reconciliation with:")
            print("  ./migrate %s activate" % migration_id)
        return 0
    print("")
    answer = input("Run next action '%s' now? [Y/n]: " % action).strip().lower()
    if answer not in ("", "y", "yes"):
        return 0
    return _dispatch(migration_id, action, [])


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="migrate",
        description="Guided EX4300-to-EX4400 migration workflow",
    )
    parser.add_argument("migration_id")
    parser.add_argument("command", nargs="?", choices=legacy.COMMANDS)
    parser.add_argument("extra", nargs=argparse.REMAINDER)
    args = parser.parse_args(values)
    try:
        if args.command is None:
            return _resume(args.migration_id)
        return _dispatch(args.migration_id, args.command, args.extra)
    except (
        OperatorError,
        provisioner_base.AnalysisError,
        provisioner_base.ProvisioningError,
        ValueError,
        OSError,
    ) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
