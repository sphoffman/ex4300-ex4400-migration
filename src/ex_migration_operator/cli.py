from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from ex_migration_analyzer.core import atomic_json, read_json, sha256_file, utc_now
from ex_migration_provisioner import cli_base as provisioner_base

from .core import (
    OperatorError,
    historical_mac_lookup,
    migration_root,
    source_address_from_evidence,
    workflow_status,
)


COMMANDS = (
    "status",
    "discover",
    "analyze",
    "build",
    "prestage",
    "cutover-ready",
    "cutover",
    "activate",
    "validate",
    "finalize",
    "mac",
)


def _run_module(module, args):
    command = [sys.executable, "-m", module] + list(args)
    result = subprocess.call(command)
    if result != 0:
        raise OperatorError(
            "workflow stopped because %s exited with status %s"
            % (module, result)
        )
    return result


def _settings(path):
    return provisioner_base.load_settings(Path(path))


def _status_text(value):
    print("EX4300 -> EX4400 Migration")
    print("Migration: %s" % value["migration_id"])
    print("")
    print("  Discovery collections: %s" % value["collections"])
    print("  Analysis:              %s" % value["analysis"])
    print("  Migration plan:        %s" % value["plan"])
    print("  Package:               %s" % value["package"])
    print("  Render:                %s" % value["render"])
    print("  Replacement identity:  %s" % value["identity"])
    print("  EX4400 pre-stage:       %s" % value["ex4400_prestage"])
    print("  Old-EX recovery:        %s" % value["old_recovery"])
    probe = value["silent_probe"]
    probe_text = probe.get("status")
    if probe.get("candidate_count") is not None:
        probe_text += " (%s candidate%s)" % (
            probe["candidate_count"],
            "" if probe["candidate_count"] == 1 else "s",
        )
    print("  Silent-port probe:      %s" % probe_text)
    print("  Physical cutover:       %s" % value["physical_cutover"])
    print("  QFX attachment:         %s" % value["qfx_attachment"])
    print("  QFX VLAN stage:         %s" % value["qfx_stage"])
    print("  Endpoint activation:    %s" % value["endpoints"])
    print("  Port-state validation:  %s" % value["port_state"])
    print("  Facilities report:      %s" % value["cabling_report"])
    print("  Final cleanup:          %s" % value["cleanup"])
    print("")
    print("Next action: %s" % value["next_action"])


def _discover(migration_id, extra):
    parser = argparse.ArgumentParser(prog="migrate %s discover" % migration_id)
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--address")
    parser.add_argument("--duration", type=int)
    parser.add_argument("--interval", type=int)
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--pause-minutes", type=float, default=0)
    parser.add_argument("--no-host-key-check", action="store_true")
    args = parser.parse_args(extra)
    if args.count < 1:
        raise OperatorError("--count must be at least 1")
    if args.pause_minutes < 0:
        raise OperatorError("--pause-minutes must not be negative")
    settings = _settings(args.settings)
    root = migration_root(settings, migration_id)
    address = args.address or source_address_from_evidence(root)
    if not address:
        address = input("Old EX4300 reachable address: ").strip()
    if not address:
        raise OperatorError(
            "the first discovery requires --address or an interactive source address"
        )

    for index in range(args.count):
        if args.count > 1:
            print("\nDiscovery collection %d of %d" % (index + 1, args.count))
        values = [
            "collect",
            address,
            "--migration-id",
            migration_id,
            "--settings",
            args.settings,
            "--port",
            str(args.port),
        ]
        if args.duration is not None:
            values += ["--duration", str(args.duration)]
        if args.interval is not None:
            values += ["--interval", str(args.interval)]
        if args.username:
            values += ["--username", args.username]
        if args.password_env:
            values += ["--password-env", args.password_env]
        if args.no_host_key_check:
            values.append("--no-host-key-check")
        _run_module("ex_migration_discovery.cli", values)
        if index + 1 < args.count and args.pause_minutes:
            seconds = int(round(args.pause_minutes * 60))
            print("Waiting %d seconds before the next independent collection..." % seconds)
            time.sleep(seconds)
    return 0


def _analyze(migration_id, extra):
    return _run_module("ex_migration_analyzer.cli", ["run", migration_id] + list(extra))


def _build(migration_id, extra):
    return _run_module("ex_migration_planner.cli", ["build", migration_id] + list(extra))


def _prestage(migration_id, extra):
    parser = argparse.ArgumentParser(prog="migrate %s prestage" % migration_id)
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--oob-address")
    parser.add_argument("--old-transport-address")
    parser.add_argument("--no-host-key-check", action="store_true")
    args = parser.parse_args(extra)
    settings = _settings(args.settings)
    root = migration_root(settings, migration_id)
    state = workflow_status(root)

    if state["package"] != "COMPLETE":
        _run_module(
            "ex_migration_provisioner.cli",
            ["prepare", migration_id, "--settings", args.settings],
        )
    state = workflow_status(root)
    if state["render"] != "COMPLETE":
        _run_module(
            "ex_migration_provisioner.cli",
            ["render", migration_id, "--settings", args.settings],
        )
    state = workflow_status(root)
    if state["identity"] != "COMPLETE":
        oob = args.oob_address or input(
            "Replacement EX4400 OOB address/prefix (for example 10.0.0.15/24): "
        ).strip()
        if not oob:
            raise OperatorError("replacement OOB address/prefix is required")
        _run_module(
            "ex_migration_provisioner.cli",
            [
                "identify",
                migration_id,
                "--settings",
                args.settings,
                "--oob-address",
                oob,
            ],
        )
    state = workflow_status(root)
    if state["ex4400_prestage"] != "COMPLETE":
        _run_module(
            "ex_migration_provisioner.cli",
            ["run", migration_id, "--settings", args.settings],
        )
    state = workflow_status(root)
    if state["old_recovery"] != "COMPLETE":
        values = ["stage-old-recovery", migration_id, "--settings", args.settings]
        if args.old_transport_address:
            values += ["--transport-address", args.old_transport_address]
        if args.no_host_key_check:
            values.append("--no-host-key-check")
        _run_module("ex_migration_provisioner.cli", values)
    return 0


def _cutover_ready(migration_id, extra):
    return _run_module(
        "ex_migration_provisioner.precutover_probe_cli",
        [migration_id] + list(extra),
    )


def _cutover(migration_id, extra):
    parser = argparse.ArgumentParser(prog="migrate %s cutover" % migration_id)
    parser.add_argument("--settings", default="config/site.json")
    parser.parse_args(extra)
    args = parser.parse_args(extra)
    settings = _settings(args.settings)
    root = migration_root(settings, migration_id)
    selected = provisioner_base.choose_approved_plan(root)
    plan_id = selected["plan"].get("plan_id")
    plan_digest = selected["plan_digest"]
    destination = root / "operator" / "physical-cutovers" / str(plan_id)
    path = destination / "ack.json"
    if path.is_file():
        integrity = read_json(destination / "integrity.json")
        if integrity.get("ack.json") != sha256_file(path):
            raise OperatorError("physical-cutover acknowledgement integrity failed")
        existing = read_json(path)
        if existing.get("approved_plan_digest") != plan_digest:
            raise OperatorError("existing physical-cutover acknowledgement is stale")
        print("Physical cutover already acknowledged for approved plan %s." % plan_id)
        return 0

    print("PHYSICAL CUTOVER CHECKPOINT")
    print("  Migration: %s" % migration_id)
    print("  Approved plan: %s" % plan_id)
    print("  This records operator acknowledgement only; it performs no device writes.")
    answer = input(
        "Confirm endpoint/uplink/recovery cabling has been physically moved and post-cutover automation may proceed? [y/N]: "
    ).strip().lower()
    if answer not in ("y", "yes"):
        print("Physical cutover was not acknowledged.")
        return 1
    value = {
        "schema_version": "1.0",
        "migration_id": migration_id,
        "approved_plan_id": plan_id,
        "approved_plan_digest": plan_digest,
        "acknowledged_at": utc_now(),
        "acknowledged": True,
    }
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(path, value)
    atomic_json(destination / "integrity.json", {"ack.json": sha256_file(path)})
    print("Physical cutover acknowledgement: RECORDED")
    return 0


def _activate(migration_id, extra):
    parser = argparse.ArgumentParser(prog="migrate %s activate" % migration_id)
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--environment", default="config/environment.lab.json")
    parser.add_argument("--no-host-key-check", action="store_true")
    args = parser.parse_args(extra)
    settings = _settings(args.settings)
    root = migration_root(settings, migration_id)
    state = workflow_status(root)
    if state["physical_cutover"] == "PENDING":
        raise OperatorError("physical cutover has not been acknowledged")

    if state["qfx_attachment"] != "COMPLETE":
        values = ["discover-attachment", migration_id, "--settings", args.settings]
        if args.no_host_key_check:
            values.append("--no-host-key-check")
        _run_module("ex_migration_provisioner.cli", values)
    state = workflow_status(root)
    if state["qfx_stage"] != "COMPLETE":
        values = [migration_id, "--settings", args.settings]
        if args.no_host_key_check:
            values.append("--no-host-key-check")
        _run_module("ex_migration_provisioner.qfx_stage_cli", values)

    _run_module(
        "ex_migration_provisioner.cli",
        [
            "activate-endpoints",
            migration_id,
            "--settings",
            args.settings,
            "--environment",
            args.environment,
        ],
    )
    return 0


def _validate(migration_id, extra):
    parser = argparse.ArgumentParser(prog="migrate %s validate" % migration_id)
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--environment", default="config/environment.lab.json")
    args = parser.parse_args(extra)
    _run_module(
        "ex_migration_provisioner.cli",
        [
            "port-state",
            migration_id,
            "--settings",
            args.settings,
            "--environment",
            args.environment,
        ],
    )
    _run_module(
        "ex_migration_provisioner.cli",
        ["cabling-report", migration_id, "--settings", args.settings],
    )
    return 0


def _finalize(migration_id, extra):
    return _run_module(
        "ex_migration_provisioner.cli",
        ["cleanup", migration_id] + list(extra),
    )


def _mac(migration_id, extra):
    parser = argparse.ArgumentParser(prog="migrate %s mac" % migration_id)
    parser.add_argument("mac_address")
    parser.add_argument("--settings", default="config/site.json")
    args = parser.parse_args(extra)
    settings = _settings(args.settings)
    result = historical_mac_lookup(migration_root(settings, migration_id), args.mac_address)
    print("Historical MAC lookup")
    print("")
    print("  Migration: %s" % result["migration_id"])
    print("  MAC: %s" % result["mac"])
    print("  Approved plan: %s" % result["approved_plan_id"])
    print("  Source analysis: %s" % result["analysis_id"])
    print("  Port consistency: %s" % result["port_consistency"])
    if not result["matches"]:
        print("  Result: MAC was not found in the approved historical EX4300 evidence.")
        return 1
    print("")
    for item in result["matches"]:
        configured = (
            "%s (%s)" % (item["configured_data_vlan_name"], item["configured_data_vlan_id"])
            if item["configured_data_vlan_id"] is not None
            else "unassigned"
        )
        observed = (
            "%s (%s)" % (item["observed_vlan_name"], item["observed_vlan_id"])
            if item["observed_vlan_id"] is not None
            else "unknown"
        )
        print("  Old port: %s" % item["interface"])
        print("    Description: %s" % (item["description"] or ""))
        print("    Configured data VLAN: %s" % configured)
        print("    MAC observed VLAN: %s" % observed)
        if item["snapshot_ids"]:
            print("    Discovery snapshots: %s" % ", ".join(item["snapshot_ids"]))
    return 0


def _dispatch(migration_id, command, extra):
    if command == "status":
        settings_parser = argparse.ArgumentParser(add_help=False)
        settings_parser.add_argument("--settings", default="config/site.json")
        args, unknown = settings_parser.parse_known_args(extra)
        if unknown:
            raise OperatorError("unrecognized status arguments: %s" % " ".join(unknown))
        value = workflow_status(migration_root(_settings(args.settings), migration_id))
        _status_text(value)
        return 0
    if command == "discover":
        return _discover(migration_id, extra)
    if command == "analyze":
        return _analyze(migration_id, extra)
    if command == "build":
        return _build(migration_id, extra)
    if command == "prestage":
        return _prestage(migration_id, extra)
    if command == "cutover-ready":
        return _cutover_ready(migration_id, extra)
    if command == "cutover":
        return _cutover(migration_id, extra)
    if command == "activate":
        return _activate(migration_id, extra)
    if command == "validate":
        return _validate(migration_id, extra)
    if command == "finalize":
        return _finalize(migration_id, extra)
    if command == "mac":
        return _mac(migration_id, extra)
    raise OperatorError("unsupported operator command %s" % command)


def _resume(migration_id):
    settings = _settings("config/site.json")
    root = migration_root(settings, migration_id)
    state = workflow_status(root)
    _status_text(state)
    action = state["next_action"]
    if action == "complete":
        print("\nMigration workflow is complete.")
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
    parser.add_argument("command", nargs="?", choices=COMMANDS)
    parser.add_argument("extra", nargs=argparse.REMAINDER)
    args = parser.parse_args(values)
    try:
        if args.command is None:
            return _resume(args.migration_id)
        return _dispatch(args.migration_id, args.command, args.extra)
    except (OperatorError, provisioner_base.AnalysisError, provisioner_base.ProvisioningError, ValueError, OSError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
