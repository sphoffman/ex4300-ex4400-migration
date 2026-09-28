from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ex_migration_analyzer.core import read_json, sha256_file

from . import cli_base as base
from .endpoint_stage import resolve_postcutover_access, validate_postcutover_access
from .inband import planned_management_ip
from .postcutover_observation import write_postcutover_observation
from .postcutover_simulator import build_simulated_postcutover_observation
from .prestage import choose_package_compat


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner simulate-postcutover",
        description=(
            "TEST ONLY: create a deterministic synthetic post-cutover EX4400 observation "
            "from the approved migration plan and replacement identity. No device connection "
            "or write is performed. The generated observation is consumed by the normal "
            "endpoint-correlation and port-state code."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument(
        "--environment",
        type=Path,
        default=Path("config/environment.lab.json"),
    )
    parser.add_argument("--identity-id")
    parser.add_argument("--package-id")
    parser.add_argument(
        "--swap-pairs",
        type=int,
        default=2,
        help=(
            "number of deterministic populated-port pairs to swap; default 2 "
            "(four moved endpoint placements)"
        ),
    )
    return parser


def _bind_lab_transport(profile, identity):
    value = dict(profile)
    access = dict(value.get("postcutover_ex_access") or {})
    if value.get("environment") != "lab" or access.get("mode") != "transport-override":
        return value

    connection = identity.get("observed", {}).get("connection", {})
    address = str(connection.get("address") or "").strip()
    transport = str(connection.get("transport_address") or address).strip()
    if not transport:
        raise base.ProvisioningError(
            "approved bootstrap identity has no pinned OOB connection address"
        )
    access["transport_address"] = transport
    value["postcutover_ex_access"] = access
    return value


def run(argv):
    args = _parser().parse_args(argv)
    if args.swap_pairs < 0:
        raise base.ProvisioningError("--swap-pairs cannot be negative")

    settings = base.load_settings(args.settings)
    migration_root = (
        Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    )
    selected_plan = base.choose_approved_plan(migration_root)
    selected_identity = base.choose_identity(migration_root, args.identity_id)
    selected_package = choose_package_compat(migration_root, args.package_id)

    plan = selected_plan["plan"]
    identity = selected_identity["identity"]
    package = selected_package["package"]
    if package.get("inputs", {}).get("plan_digest") != selected_plan["plan_digest"]:
        raise base.ProvisioningError(
            "selected pre-stage package is bound to a different approved migration plan"
        )

    profile = _bind_lab_transport(read_json(args.environment), identity)
    profile = validate_postcutover_access(profile)
    access = resolve_postcutover_access(profile, planned_management_ip(plan))

    result = build_simulated_postcutover_observation(
        args.migration_id,
        plan,
        selected_plan["plan_digest"],
        identity,
        sha256_file(selected_identity["identity_path"]),
        package,
        sha256_file(selected_package["package_path"]),
        access,
        swap_pairs=args.swap_pairs,
    )
    observation = result["observation"]
    destination, observation, action = write_postcutover_observation(
        migration_root,
        observation,
        result["mac_table_text"],
        result["terse_text"],
    )

    scenario = result["scenario"]
    stats = scenario["statistics"]
    print("\nSynthetic post-cutover EX4400 observation")
    print("  Migration: %s" % args.migration_id)
    print("  Scenario: %s" % scenario["name"])
    print("  Plan: %s" % plan["plan_id"])
    print("  Identity: %s" % identity["identity_id"])
    print("  Package: %s" % package["package_id"])
    print("  Correlatable endpoint intents: %d" % stats["correlatable_endpoint_intents"])
    print("  Approved endpoint MACs: %d" % stats["approved_endpoint_macs"])
    print("  Same-position placements: %d" % stats["same_position_placements"])
    print("  Moved placements: %d" % stats["moved_placements"])
    print("  Missing endpoints: %d" % stats["missing_endpoints"])
    print("  Unexpected endpoints: %d" % stats["unexpected_endpoints"])

    print("\n  Cable mutations:")
    if scenario["mutations"]:
        for pair in scenario["mutations"]:
            a = pair["a"]
            b = pair["b"]
            print(
                "    %s -> %s"
                % (a["old_interface"], a["new_interface"])
            )
            print(
                "    %s -> %s"
                % (b["old_interface"], b["new_interface"])
            )
    else:
        print("    none")

    obs_stats = observation["statistics"]
    print("\nPost-cutover observation: VALID")
    print("  Observation: %s (%s)" % (observation["observation_id"], action))
    print("  Source: %s" % observation["source"]["kind"])
    print(
        "  Physical interfaces observed: %d"
        % obs_stats["physical_interfaces_observed"]
    )
    print(
        "  Dynamic MACs observed: %d"
        % obs_stats["unique_dynamic_macs"]
    )
    print("  Integrity: PASS")
    print("  Record: %s" % (destination / "observation.json"))
    print("  Device connections performed: no")
    print("  Device writes performed: no")

    print("\nUse this exact observation with normal production consumers:")
    print(
        "  python -m ex_migration_provisioner.endpoint_stage_cli %s "
        "--observation-id %s"
        % (args.migration_id, observation["observation_id"])
    )
    print(
        "  python -m ex_migration_provisioner.port_state_cli %s "
        "--observation-id %s"
        % (args.migration_id, observation["observation_id"])
    )
    return 0


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    try:
        return run(values)
    except (
        base.AnalysisError,
        base.ProvisioningError,
        base.WriteError,
        OSError,
        ValueError,
    ) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
