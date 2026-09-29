from __future__ import annotations

import argparse
import csv
import ipaddress
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

    if progress["accepted_count"]:
        print(
            "\n%d endpoint intent(s) remain unresolved but are covered by accepted exception(s)."
            % progress["accepted_count"]
        )
        print("They are not marked migrated and remain eligible for later reconciliation.")
        print("Run './migrate %s activate' later to retry them." % root.name)
        return 0

    if not progress["unresolved"]:
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
    if "--plan-only" in extra:
        return 0
    settings_parser = argparse.ArgumentParser(add_help=False)
    settings_parser.add_argument("--settings", default="config/site.json")
    args, _unknown = settings_parser.parse_known_args(extra)
    root = migration_root(legacy._settings(args.settings), migration_id)
    return _offer_exception_acceptance(root)


def _inventory_path(settings):
    return Path(settings.get("ex4400_inventory_csv", "data/ex4400_inventory.csv"))


def _inventory_row(settings, migration_id):
    """Return a READY inventory row, or None when this migration is not inventoried."""
    path = _inventory_path(settings)
    if not path.is_file():
        return None

    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    wanted = str(migration_id).strip().lower()
    matches = [
        row
        for row in rows
        if str(row.get("migration_id") or "").strip().lower() == wanted
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise OperatorError(
            "EX4400 inventory %s contains %d rows for migration %s; expected exactly one"
            % (path, len(matches), migration_id)
        )

    row = matches[0]
    status = str(row.get("status") or "").strip()
    if status != "READY":
        raise OperatorError(
            "EX4400 inventory row for %s is not READY (status=%s); refusing to bypass inventory safety"
            % (migration_id, status or "UNKNOWN")
        )
    return row


def _inventory_ex4300_address(row, migration_id):
    address = str(row.get("ex4300_ip") or "").strip()
    if not address:
        raise OperatorError(
            "READY EX4400 inventory row for %s has no ex4300_ip" % migration_id
        )
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        raise OperatorError(
            "READY EX4400 inventory row for %s has invalid ex4300_ip %r"
            % (migration_id, address)
        )
    if parsed.version != 4:
        raise OperatorError("EX4300 inventory address must be IPv4")
    return str(parsed)


def _inventory_ex4400_oob(row, migration_id):
    address = str(row.get("ex4400_ip") or "").strip()
    network = str(row.get("management_network") or "").strip()
    if not address:
        raise OperatorError(
            "READY EX4400 inventory row for %s has no ex4400_ip" % migration_id
        )
    if not network:
        raise OperatorError(
            "READY EX4400 inventory row for %s has no management_network; cannot derive the VME/OOB CIDR"
            % migration_id
        )
    try:
        parsed_address = ipaddress.ip_address(address)
        parsed_network = ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        raise OperatorError(
            "READY EX4400 inventory row for %s has invalid management addressing: %s"
            % (migration_id, exc)
        )
    if parsed_address.version != 4 or parsed_network.version != 4:
        raise OperatorError("EX4400 VME/OOB inventory addressing must be IPv4")
    if parsed_address not in parsed_network:
        raise OperatorError(
            "EX4400 inventory address %s is not inside management network %s"
            % (parsed_address, parsed_network)
        )
    return "%s/%d" % (parsed_address, parsed_network.prefixlen)


def _validated_oob_address(value):
    value = str(value or "").strip()
    if not value:
        raise OperatorError("replacement VME/OOB address/prefix is required")
    if "/" not in value:
        raise OperatorError(
            "replacement VME/OOB address must include an explicit CIDR prefix "
            "(for example 10.255.3.16/24); refusing to assume /32"
        )
    try:
        parsed = ipaddress.ip_interface(value)
    except ValueError:
        raise OperatorError(
            "replacement VME/OOB address/prefix is not valid IPv4 CIDR: %s" % value
        )
    if parsed.version != 4:
        raise OperatorError("replacement VME/OOB address must be IPv4 CIDR")
    return value


def _discover_with_inventory(migration_id, extra):
    values = list(extra)
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--address")
    args, _unknown = parser.parse_known_args(values)
    if args.address:
        return legacy._dispatch(migration_id, "discover", values)

    settings = legacy._settings(args.settings)
    row = _inventory_row(settings, migration_id)
    if row is None:
        return legacy._dispatch(migration_id, "discover", values)

    address = _inventory_ex4300_address(row, migration_id)
    root = migration_root(settings, migration_id)
    evidence_address = legacy.source_address_from_evidence(root)
    if evidence_address and str(evidence_address) != address:
        raise OperatorError(
            "EX4400 inventory EX4300 address %s conflicts with existing discovery evidence %s for %s"
            % (address, evidence_address, migration_id)
        )

    print(
        "EX4300 address: %s (from %s)"
        % (address, _inventory_path(settings))
    )
    values += ["--address", address]
    return legacy._dispatch(migration_id, "discover", values)


def _prestage_with_validated_oob(migration_id, extra):
    values = list(extra)
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--oob-address")
    args, _unknown = parser.parse_known_args(values)
    settings = legacy._settings(args.settings)
    root = migration_root(settings, migration_id)
    state = workflow_status(root)
    if state.get("identity") == "COMPLETE":
        return legacy._dispatch(migration_id, "prestage", values)

    oob = args.oob_address
    if oob is None:
        row = _inventory_row(settings, migration_id)
        if row is not None:
            oob = _inventory_ex4400_oob(row, migration_id)
            print(
                "Replacement EX4400 VME/OOB address: %s (from %s)"
                % (oob, _inventory_path(settings))
            )
        else:
            oob = input(
                "Replacement EX4400 VME/OOB address/prefix (for example 10.0.0.15/24): "
            ).strip()
        values += ["--oob-address", _validated_oob_address(oob)]
    else:
        _validated_oob_address(oob)
    return legacy._dispatch(migration_id, "prestage", values)


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
    if command == "discover":
        return _discover_with_inventory(migration_id, extra)
    if command == "prestage":
        return _prestage_with_validated_oob(migration_id, extra)
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

    result = _dispatch(migration_id, action, [])
    if result != 0:
        return result

    # Build and prestage are one operator preparation phase. Preserve both
    # approval scopes, but do not force a second shell invocation between them.
    if action == "build":
        state = workflow_status(root)
        if state.get("next_action") == "prestage":
            print("\nMigration intent approved; continuing directly into pre-stage preparation.")
            return _dispatch(migration_id, "prestage", [])
    return result


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
