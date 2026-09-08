from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ex_migration_analyzer.core import sha256_file, utc_now

from . import cli_base as base
from .prestage import validate_pre_cutover_site_policy
from .qfx_stage import (
    build_qfx_vlan_plan,
    choose_attachment,
    write_qfx_vlan_plan,
)


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner prepare-qfx",
        description=(
            "POST-CUTOVER READ ONLY: revalidate the approved QFX attachment, derive "
            "only the production VLANs required by approved endpoint/voice intent, "
            "resolve those VLANs in the existing MAC-VRF on both QFXs, and create an "
            "immutable QFX AE-membership plan. No writes are performed."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--site-policy", type=Path)
    parser.add_argument("--attachment-id")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument(
        "--no-host-key-check",
        action="store_true",
        help="LAB ONLY: disable NETCONF known-host verification; the attachment-pinned SSH fingerprint is still rechecked",
    )
    return parser


def _print_plan(value):
    print("\nPost-cutover QFX VLAN plan")
    print("  Attachment: %s" % value["inputs"]["attachment_id"])
    print(
        "  Required production VLANs: %s"
        % ", ".join(str(v) for v in value["derivation"]["required_vlan_ids"])
    )
    excluded = value["derivation"]["configured_but_not_required_vlan_ids"]
    if excluded:
        print(
            "  Configured on EX but not required on QFX AE: %s"
            % ", ".join(str(v) for v in excluded)
        )
    for item in sorted(value["devices"], key=lambda row: row["role"]):
        print(
            "  %s %s: %s -> %s in %s : %s"
            % (
                item["role"],
                item["management_address"],
                item["physical_interface"] or "UNRESOLVED",
                item["ae_interface"] or "UNRESOLVED",
                item["routing_instance"] or "UNRESOLVED",
                item["result"],
            )
        )
        if item["required_vlans"]:
            print(
                "    Resolved VLANs: %s"
                % ", ".join(
                    "%s=%s" % (row["vlan_id"], row["name"])
                    for row in item["required_vlans"]
                )
            )
        for statement in item["statements"]:
            print("    + %s" % statement)
        for name, passed in item["checks"].items():
            if not passed:
                print("    FAIL: %s" % name)
        for failure in item["resolution_failures"]:
            print(
                "    FAIL VLAN %s: %s"
                % (failure["vlan_id"], failure["reason"])
            )
    for name, passed in value["pair_checks"].items():
        if not passed:
            print("  Pair FAIL: %s" % name)
    print("  Result: %s" % value["result"])


def run(argv):
    args = _parser().parse_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected_plan = base.choose_approved_plan(migration_root)
    selected_attachment = choose_attachment(migration_root, args.attachment_id)

    paths = base._provisioning_paths(settings)
    if args.site_policy:
        paths["site_policy"] = args.site_policy
    base._require_paths(paths)
    policy = validate_pre_cutover_site_policy(base.read_json(paths["site_policy"]))
    if args.no_host_key_check and policy["environment"] != "lab":
        raise base.ProvisioningError("--no-host-key-check is permitted only by a lab QFX site policy")

    username, password = base._credentials(args, "QFX")

    from jnpr.junos import Device

    devices = {}
    host_keys = {}
    opened = []
    try:
        for device_policy in policy["qfx_pair"]:
            role = device_policy["role"]
            address = device_policy["management_address"]
            print("Connecting read-only to %s at %s..." % (device_policy["expected_hostname"], address))
            host_keys[role] = base.ssh_host_key_fingerprint(address, args.port)
            dev = Device(
                host=address,
                user=username,
                passwd=password,
                port=args.port,
                gather_facts=True,
            )
            dev.open(auto_probe=10, hostkey_verify=not args.no_host_key_check)
            devices[role] = dev
            opened.append(dev)

        value = build_qfx_vlan_plan(
            args.migration_id,
            selected_plan["plan"],
            selected_plan["plan_digest"],
            selected_attachment["attachment"],
            sha256_file(selected_attachment["attachment_path"]),
            policy,
            sha256_file(paths["site_policy"]),
            devices,
            host_keys,
            created_at=utc_now(),
        )
    except base.ProvisioningError:
        raise
    except Exception as exc:
        raise base.ProvisioningError("post-cutover QFX VLAN planning failed: %s" % exc)
    finally:
        for dev in reversed(opened):
            try:
                dev.close()
            except Exception:
                pass

    _print_plan(value)
    if value["result"] != "PASS":
        raise base.ProvisioningError("QFX VLAN plan failed validation; no plan artifact was created")

    destination, value, action = write_qfx_vlan_plan(migration_root, value)
    print("\nQFX VLAN plan: %s (%s)" % (value["qfx_plan_id"], action))
    print("  Plan: %s" % (destination / "plan.json"))
    print("  QFX writes performed: no")
    print("  EX4400 writes performed: no")
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
