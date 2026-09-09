from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from ex_migration_analyzer.core import read_json, utc_now
from ex_migration_discovery.collector import Collector

from . import cli_base as base
from .precutover_probe import (
    analysis_for_approved_plan,
    build_probe_record,
    eligible_interfaces,
    live_candidate_state,
    silent_candidates,
    write_probe_record,
)


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner pre-cutover-probe",
        description=(
            "Guarded pre-cutover probe for access ports that were silent in the analysis "
            "bound to the currently approved migration plan. The command rechecks each "
            "candidate live, briefly disables only still-silent admin/oper-up access ports, "
            "re-enables them, then creates a normal discovery collection so newly awakened "
            "clients enter the existing analyzer evidence model."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--down-seconds", type=int, default=5)
    parser.add_argument("--relearn-seconds", type=int, default=30)
    parser.add_argument("--observation-seconds", type=int, default=120)
    parser.add_argument("--interval-seconds", type=int, default=30)
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="connect read-only, show the exact currently eligible silent-port candidates, and perform no writes",
    )
    parser.add_argument(
        "--no-host-key-check",
        action="store_true",
        help="LAB ONLY: disable NETCONF known-host verification",
    )
    return parser


def _source_address(migration_root):
    manifest_path = migration_root / "manifest.json"
    if not manifest_path.is_file():
        raise base.ProvisioningError("migration manifest is missing: %s" % manifest_path)
    manifest = read_json(manifest_path)
    old_switch = manifest.get("old_switch", {})
    value = str(old_switch.get("connection_address") or old_switch.get("management_address") or "").strip()
    if not value:
        raise base.ProvisioningError("migration manifest has no old-switch connection address")
    return value


def _live_state(dev, candidates):
    interfaces = dev.cli(
        "show configuration interfaces | display inheritance | display set",
        warning=False,
    ) or ""
    vlans = dev.cli(
        "show configuration vlans | display inheritance | display set",
        warning=False,
    ) or ""
    terse = dev.cli("show interfaces terse", warning=False) or ""
    mac_detail = dev.cli("show ethernet-switching table detail", warning=False) or ""
    return live_candidate_state(
        interfaces + "\n" + vlans,
        terse,
        mac_detail,
        candidates,
        observed_at=utc_now(),
    )


def _show_candidates(rows):
    eligible = [row for row in rows if row.get("eligible")]
    skipped = [row for row in rows if not row.get("eligible")]
    print("\nSilent-port pre-cutover candidates")
    print("  Eligible to bounce now: %d" % len(eligible))
    for row in eligible:
        vlan = row.get("live_data_vlan_id")
        print(
            "    %s | %s | VLAN %s | admin %s / oper %s"
            % (
                row["interface"],
                row["analysis_disposition"],
                vlan if vlan is not None else "unassigned",
                row.get("live_admin_status"),
                row.get("live_oper_status"),
            )
        )
    if skipped:
        print("  Skipped by live safety recheck: %d" % len(skipped))
        for row in skipped:
            print("    %s | %s" % (row["interface"], row.get("skip_reason")))
    return eligible


def _restore_enabled(config, interfaces, migration_id):
    if not interfaces:
        return []
    errors = []
    try:
        config.rollback()
    except Exception:
        pass
    try:
        payload = "\n".join("delete interfaces %s disable" % interface for interface in sorted(interfaces)) + "\n"
        config.load(payload, format="set", merge=True)
        if config.commit_check() is not True:
            raise base.ProvisioningError("emergency re-enable commit-check did not return PASS")
        if config.commit(
            comment="Emergency restore EX migration %s pre-cutover silent probe" % migration_id,
            timeout=120,
        ) is not True:
            raise base.ProvisioningError("emergency re-enable commit did not return success")
    except Exception as exc:
        errors.append(str(exc))
    return errors


def run(argv):
    args = _parser().parse_args(argv)
    for name, value in (
        ("--down-seconds", args.down_seconds),
        ("--relearn-seconds", args.relearn_seconds),
        ("--observation-seconds", args.observation_seconds),
    ):
        if value < 0:
            raise base.ProvisioningError("%s must not be negative" % name)
    if args.interval_seconds < 1:
        raise base.ProvisioningError("--interval-seconds must be at least 1")

    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected_plan = base.choose_approved_plan(migration_root)
    plan = selected_plan["plan"]
    if args.no_host_key_check and bool(plan.get("eligibility", {}).get("production_eligible")):
        raise base.ProvisioningError("--no-host-key-check is prohibited for a production-eligible migration plan")

    analysis, _analysis_path, analysis_digest = analysis_for_approved_plan(migration_root, selected_plan)
    candidates = silent_candidates(analysis)
    print("Pre-cutover silent-port probe")
    print("  Migration: %s" % args.migration_id)
    print("  Approved plan: %s" % plan.get("plan_id"))
    print("  Bound analysis: %s" % analysis.get("analysis_id"))
    print("  Silent candidates in bound analysis: %d" % len(candidates))
    if not candidates:
        print("  Result: no silent ports require probing")
        print("  Device writes performed: no")
        return 0

    source_address = _source_address(migration_root)
    username, password = base._credentials(args, "old EX4300")

    from jnpr.junos import Device
    from jnpr.junos.utils.config import Config

    dev = Device(
        host=source_address,
        user=username,
        passwd=password,
        port=args.port,
        gather_facts=True,
    )
    config = None
    locked = False
    disabled_by_probe = set()
    started_at = utc_now()
    try:
        print("  Connecting to old switch at %s:%s..." % (source_address, args.port))
        dev.open(auto_probe=10, hostkey_verify=not args.no_host_key_check)
        facts = getattr(dev, "facts", {}) or {}
        observed_hostname = str(facts.get("hostname") or "").strip()
        expected_hostname = str(plan.get("template_variables", {}).get("old_hostname") or "").strip()
        if not expected_hostname:
            raise base.ProvisioningError("approved plan has no old-switch hostname")
        if observed_hostname.lower() != expected_hostname.lower():
            raise base.ProvisioningError(
                "connected source hostname %r does not match approved old-switch hostname %r"
                % (observed_hostname, expected_hostname)
            )

        initial_state = _live_state(dev, candidates)
        initial_eligible = _show_candidates(initial_state)
        approved_interfaces = eligible_interfaces(initial_state)
        if not approved_interfaces:
            print("\nNo ports remain eligible after the live safety check.")
            print("Device writes performed: no")
            return 0
        if args.plan_only:
            print("\nPlan-only result: PASS")
            print("Device writes performed: no (--plan-only)")
            return 0

        print("\nProbe behavior")
        print("  Ports will be disabled together for %d seconds." % args.down_seconds)
        print("  Every touched port will then be re-enabled before observation begins.")
        print("  Relearn delay after re-enable: %d seconds." % args.relearn_seconds)
        print("  Follow-up discovery observation: %d seconds at %d-second intervals." % (
            args.observation_seconds,
            args.interval_seconds,
        ))
        answer = input(
            "\nApprove temporary disable/re-enable of exactly the %d eligible silent port(s) above? [y/N]: "
            % len(approved_interfaces)
        ).strip().lower()
        if answer not in ("y", "yes"):
            print("Probe was not approved; no configuration change was performed.")
            return 1

        config = Config(dev)
        config.lock()
        locked = True
        if config.diff():
            raise base.ProvisioningError("old switch candidate already contains uncommitted changes")

        locked_state = _live_state(
            dev,
            [row for row in candidates if row["interface"] in set(approved_interfaces)],
        )
        locked_interfaces = eligible_interfaces(locked_state)
        skipped_after_approval = sorted(set(approved_interfaces) - set(locked_interfaces))
        if skipped_after_approval:
            print("\nSafety recheck skipped ports that changed after approval:")
            by_interface = {row["interface"]: row for row in locked_state}
            for interface in skipped_after_approval:
                print("  %s | %s" % (interface, by_interface[interface].get("skip_reason")))
        if not locked_interfaces:
            print("No approved port remains eligible after lock-time recheck; no writes performed.")
            return 0

        disable_payload = "\n".join(
            "set interfaces %s disable" % interface for interface in locked_interfaces
        ) + "\n"
        config.load(disable_payload, format="set", merge=True)
        if config.commit_check() is not True:
            raise base.ProvisioningError("silent-port disable commit-check did not return PASS")
        diff = config.diff() or ""
        print("\nDisable candidate diff")
        print(diff.rstrip())
        if config.commit(
            comment="EX migration %s pre-cutover silent-port probe disable" % args.migration_id,
            timeout=120,
        ) is not True:
            raise base.ProvisioningError("silent-port disable commit did not return success")
        disabled_by_probe.update(locked_interfaces)

        if args.down_seconds:
            time.sleep(args.down_seconds)

        enable_payload = "\n".join(
            "delete interfaces %s disable" % interface for interface in locked_interfaces
        ) + "\n"
        config.load(enable_payload, format="set", merge=True)
        if config.commit_check() is not True:
            raise base.ProvisioningError("silent-port re-enable commit-check did not return PASS")
        if config.commit(
            comment="EX migration %s pre-cutover silent-port probe re-enable" % args.migration_id,
            timeout=120,
        ) is not True:
            raise base.ProvisioningError("silent-port re-enable commit did not return success")
        disabled_by_probe.clear()
        config.unlock()
        locked = False

        if args.relearn_seconds:
            print("\nPorts restored; waiting %d seconds for client relearn..." % args.relearn_seconds)
            time.sleep(args.relearn_seconds)

        print("Starting post-bounce discovery collection...")
        collector = Collector(
            dev,
            Path(settings["snapshot_root"]),
            args.observation_seconds,
            args.interval_seconds,
            args.migration_id,
            management_vlan_id=int(settings.get("default_management_vlan_id", 163)),
            connection_address=source_address,
        )
        collection_path = collector.run()
        collection_snapshot = read_json(collection_path / "snapshot.json")
        relative_collection = collection_path.relative_to(migration_root)
        record = build_probe_record(
            args.migration_id,
            selected_plan,
            analysis,
            analysis_digest,
            source_address,
            observed_hostname,
            initial_state,
            approved_interfaces,
            locked_state,
            relative_collection,
            collection_snapshot,
            started_at,
            completed_at=utc_now(),
        )
        destination, action = write_probe_record(migration_root, record)

        discovered = record["discovered_candidate_macs"]
        print("\nPre-cutover silent-port probe: PASS")
        print("  Ports bounced: %d" % len(locked_interfaces))
        print("  Post-bounce collection: %s" % relative_collection)
        print("  Probe record: %s (%s)" % (destination / "probe.json", action))
        if discovered:
            count = sum(len(items) for items in discovered.values())
            print("  Newly awakened client observations: %d" % count)
            for interface, items in sorted(discovered.items()):
                for item in items:
                    print("    %s | %s | VLAN %s" % (interface, item["mac"], item["vlan_id"]))
            print("\nCUTOVER HOLD: new client evidence was found.")
            print("Rerun analyzer and planner so the migration intent includes this evidence before cutover.")
        else:
            print("  Newly awakened client observations: 0")
            print("  No new client evidence was discovered by the bounce.")
        return 0

    except Exception as exc:
        if config is not None and disabled_by_probe:
            errors = _restore_enabled(config, disabled_by_probe, args.migration_id)
            disabled_by_probe.clear()
            if errors:
                raise base.ProvisioningError(
                    "%s; emergency port re-enable failed: %s" % (exc, "; ".join(errors))
                )
        if isinstance(exc, (base.AnalysisError, base.ProvisioningError, base.WriteError, OSError, ValueError)):
            raise
        raise base.ProvisioningError(str(exc))
    finally:
        if locked and config is not None:
            try:
                config.unlock()
            except Exception:
                pass
        try:
            dev.close()
        except Exception:
            pass


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    try:
        return run(values)
    except (base.AnalysisError, base.ProvisioningError, base.WriteError, OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
