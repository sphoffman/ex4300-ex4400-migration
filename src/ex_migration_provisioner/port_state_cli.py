from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ex_migration_analyzer.core import read_json, utc_now

from . import cli_base as base
from .endpoint_stage import (
    committed_endpoint_state,
    resolve_postcutover_access,
    validate_postcutover_access,
)
from .endpoint_stage_cli import (
    _bind_lab_identity_transport,
    _interfaces_config_set,
    _reconcile_completed_state,
    _recovery_interface,
    _validate_postcutover_identity,
)
from .inband import planned_management_ip
from .port_state import (
    build_port_state_comparison,
    load_approved_port_state_evidence,
    write_port_state_comparison,
)
from .prestage import choose_package_compat


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner port-state",
        description=(
            "POST-CUTOVER READ-ONLY: reconstruct old-switch per-sample access-port state from "
            "the discovery collections bound to the approved migration plan, compare it with "
            "the replacement EX4400, and infer same-position ports only as advisory evidence."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--environment", type=Path, default=Path("config/environment.lab.json"))
    parser.add_argument("--identity-id")
    parser.add_argument("--package-id")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    return parser


def _interesting(row):
    pre = row.get("pre_migration") or {}
    state = pre.get("latest_state")
    return (
        row.get("mapping_source") == "SAME_PHYSICAL_POSITION_ADVISORY"
        or state in ("UP_SILENT", "LINK_DOWN", "ADMIN_DOWN")
        or row.get("state_match") is False
        or not row.get("candidate_new_interface")
    )


def run(argv):
    args = _parser().parse_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id

    selected_plan = base.choose_approved_plan(migration_root)
    selected_identity = base.choose_identity(migration_root, args.identity_id)
    selected_package = choose_package_compat(migration_root, args.package_id)
    package = selected_package["package"]
    if package.get("inputs", {}).get("plan_digest") != selected_plan["plan_digest"]:
        raise base.ProvisioningError(
            "selected pre-stage package is bound to a different approved migration plan"
        )

    profile = read_json(args.environment)
    profile = _bind_lab_identity_transport(profile, selected_identity["identity"])
    profile = validate_postcutover_access(profile)
    management_ip = planned_management_ip(selected_plan["plan"])
    access = resolve_postcutover_access(profile, management_ip)

    variables = package.get("variables", {})
    uplink_interfaces = variables.get("uplink_interfaces")
    if not isinstance(uplink_interfaces, list) or not uplink_interfaces:
        raise base.ProvisioningError(
            "selected pre-stage package has no explicit uplink inventory"
        )
    recovery_interface = str(
        variables.get("recovery_interface")
        or _recovery_interface(selected_identity["identity"])
    )

    print("Reconstructing approved pre-migration port-state history...")
    pre_evidence = load_approved_port_state_evidence(
        migration_root,
        selected_plan["plan"],
        selected_plan["plan_digest"],
    )
    historical_completed = committed_endpoint_state(
        migration_root,
        selected_plan["plan_digest"],
    )

    username, password = base._credentials(args, "EX4400")
    transport = access["transport_address"]
    port = access["port"]
    current_fingerprint = base.ssh_host_key_fingerprint(transport, port)
    bound_fingerprint = (
        selected_identity["identity"]
        .get("observed", {})
        .get("connection", {})
        .get("ssh_host_key_sha256")
    )
    if current_fingerprint != bound_fingerprint:
        raise base.ProvisioningError(
            "post-cutover EX transport SSH key does not match the approved bootstrap identity"
        )

    from jnpr.junos import Device

    dev = Device(
        host=transport,
        user=username,
        passwd=password,
        port=port,
        gather_facts=True,
    )
    try:
        dev.open(auto_probe=10, hostkey_verify=False)
        current = base.observe_ex4400_identity(
            dev,
            management_ip,
            port,
            current_fingerprint,
            allow_vjunos_switch=access["allow_vjunos_switch"],
        )
        expected_hostname = str(
            selected_plan["plan"].get("template_variables", {}).get("new_hostname") or ""
        )
        _validate_postcutover_identity(
            current,
            selected_identity["identity"],
            expected_hostname,
        )
        committed_config = _interfaces_config_set(dev, "committed")
        completed = _reconcile_completed_state(committed_config, historical_completed)
        terse_text = dev.cli("show interfaces terse", warning=False) or ""
        mac_text = dev.cli("show ethernet-switching table extensive", warning=False) or ""
    except base.ProvisioningError:
        raise
    except Exception as exc:
        raise base.ProvisioningError("EX4400 port-state observation failed: %s" % exc)
    finally:
        try:
            dev.close()
        except Exception:
            pass

    observed_at = utc_now()
    comparison = build_port_state_comparison(
        args.migration_id,
        selected_plan["plan"],
        selected_plan["plan_digest"],
        pre_evidence,
        terse_text,
        mac_text,
        recovery_interface,
        uplink_interfaces=uplink_interfaces,
        completed=completed,
        observed_at=observed_at,
    )
    comparison["historical_completions_reopened"] = completed.get("stale", [])
    destination, action = write_port_state_comparison(
        migration_root,
        comparison,
        terse_text,
        mac_text,
    )

    stats = comparison["statistics"]
    pre_counts = stats["pre_latest_state_counts"]
    print("\nPost-cutover port-state comparison")
    print("  Logical target: %s:%s" % (access["logical_address"], access["port"]))
    if access["transport_address"] != access["logical_address"]:
        print("  Lab transport: %s:%s" % (access["transport_address"], access["port"]))
    print("  Approved discovery collections: %d" % len(pre_evidence.get("collections", [])))
    print("  Discovery sample runs reconstructed: %d" % pre_evidence.get("total_sample_runs", 0))
    print("  Pre-migration latest states:")
    print("    ACTIVE_MAC: %d" % pre_counts.get("ACTIVE_MAC", 0))
    print("    UP_SILENT:  %d" % pre_counts.get("UP_SILENT", 0))
    print("    LINK_DOWN:  %d" % pre_counts.get("LINK_DOWN", 0))
    print("    ADMIN_DOWN: %d" % pre_counts.get("ADMIN_DOWN", 0))
    print("  Confirmed endpoint mappings present in current config: %d" % stats["confirmed_mappings"])
    print("  Historical completions reopened: %d" % len(completed.get("stale", [])))
    print("  Same-position advisory candidates: %d" % stats["same_position_advisories"])
    print("  Same-position state matches: %d" % stats["same_position_state_matches"])
    print("  Same-position state mismatches: %d" % stats["same_position_state_mismatches"])
    print("  Unresolved candidate ports: %d" % stats["unresolved_candidates"])

    rows = [row for row in comparison["rows"] if _interesting(row)]
    if rows:
        print("\n  Silent/down/advisory details:")
        for row in rows:
            pre = row.get("pre_migration") or {}
            post = row.get("post_migration") or {}
            candidate = row.get("candidate_new_interface") or "unresolved"
            match = (
                "MATCH" if row.get("state_match") is True
                else "MISMATCH" if row.get("state_match") is False
                else "N/A"
            )
            print(
                "    %s -> %s | pre %s | post %s | %s | %s"
                % (
                    row["old_interface"],
                    candidate,
                    pre.get("latest_state") or "unknown",
                    post.get("state") or "unknown",
                    match,
                    row["confidence"],
                )
            )
            if pre.get("samples"):
                counts = pre.get("counts", {})
                print(
                    "      discovery samples %d: active=%d up-silent=%d link-down=%d admin-down=%d"
                    % (
                        pre["samples"],
                        counts.get("ACTIVE_MAC", 0),
                        counts.get("UP_SILENT", 0),
                        counts.get("LINK_DOWN", 0),
                        counts.get("ADMIN_DOWN", 0),
                    )
                )
            if row.get("mapping_source") == "SAME_PHYSICAL_POSITION_ADVISORY":
                print("      basis: same physical port position; advisory only, never VLAN authorization")
            elif row.get("candidate_reason"):
                print("      candidate: %s" % row["candidate_reason"])
    else:
        print("\n  No silent/down/advisory ports require attention in this observation.")

    print("\nPort-state comparison: %s (%s)" % (comparison["comparison_id"], action))
    print("  Report: %s" % (destination / "report.md"))
    print("  Record: %s" % (destination / "comparison.json"))
    print("  Device writes performed: no")
    print("  Endpoint activation authorization derived from state-only evidence: no")
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
