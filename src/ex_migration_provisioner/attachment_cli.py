from __future__ import annotations

import argparse
from pathlib import Path

from ex_migration_analyzer.core import sha256_file, utc_now

from . import cli_base as base
from .attachment import (
    build_attachment_artifact,
    discover_qfx_attachment,
    write_attachment,
)
from .prestage import validate_pre_cutover_site_policy


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner discover-attachment",
        description=(
            "POST-CUTOVER READ ONLY: discover the target EX4400 by LLDP on both "
            "QFXs, learn the existing physical-port-to-AE attachment, require "
            "pair symmetry, and optionally bind the exact observation."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--site-policy", type=Path)
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument(
        "--no-host-key-check",
        action="store_true",
        help="LAB ONLY: disable NETCONF known-host verification; the observed SSH fingerprint is still recorded",
    )
    return parser


def _print_discovery(discovery):
    print("\nPost-cutover QFX attachment discovery")
    print("  Target EX4400: %s" % discovery["expected_ex_hostname"])
    for item in sorted(discovery["devices"], key=lambda value: value["role"]):
        print(
            "  %s %s (%s): %s -> %s : %s"
            % (
                item["expected_qfx_hostname"],
                item["management_address"],
                item["observed_qfx_model"] or "unknown-model",
                item["physical_interface"] or "UNRESOLVED",
                item["ae_interface"] or "UNRESOLVED",
                item["result"],
            )
        )
        print("    LLDP peer: %s" % item["expected_ex_hostname"])
        if item.get("remote_port_id"):
            print("    LLDP remote port: %s" % item["remote_port_id"])
        if item.get("lacp_system_id"):
            print("    LACP system ID: %s" % item["lacp_system_id"])
        if item.get("baseline_vlan_ids") is not None:
            print(
                "    Baseline VLANs: %s"
                % ", ".join(str(value) for value in item["baseline_vlan_ids"])
            )
        if item["result"] != "PASS":
            for name, passed in item["checks"].items():
                if not passed:
                    print("    FAIL: %s" % name)
            if item.get("unresolved_vlan_members"):
                print(
                    "    Unresolved VLAN members: %s"
                    % ", ".join(item["unresolved_vlan_members"])
                )

    for name, passed in discovery["pair_checks"].items():
        if not passed:
            print("  Pair FAIL: %s" % name)
    print("  Result: %s" % discovery["result"])


def run(argv):
    args = _parser().parse_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected = base.choose_approved_plan(migration_root)
    expected_ex_hostname = str(
        selected["plan"].get("template_variables", {}).get("new_hostname") or ""
    ).strip()
    if not expected_ex_hostname:
        raise base.ProvisioningError("approved migration plan has no target EX4400 hostname")

    paths = base._provisioning_paths(settings)
    if args.site_policy:
        paths["site_policy"] = args.site_policy
    base._require_paths(paths)
    policy = validate_pre_cutover_site_policy(base.read_json(paths["site_policy"]))
    if args.no_host_key_check and policy["environment"] != "lab":
        raise base.ProvisioningError(
            "--no-host-key-check is permitted only by a lab QFX site policy"
        )

    username, password = base._credentials(args, "QFX")

    from jnpr.junos import Device

    devices = {}
    host_keys = {}
    opened = []
    try:
        for device_policy in policy["qfx_pair"]:
            role = device_policy["role"]
            address = device_policy["management_address"]
            print(
                "Connecting read-only to %s at %s..."
                % (device_policy["expected_hostname"], address)
            )
            host_keys[role] = base.ssh_host_key_fingerprint(address, args.port)
            dev = Device(
                host=address,
                user=username,
                passwd=password,
                port=args.port,
                gather_facts=True,
            )
            dev.open(
                auto_probe=10,
                hostkey_verify=not args.no_host_key_check,
            )
            devices[role] = dev
            opened.append(dev)

        discovery = discover_qfx_attachment(
            policy,
            expected_ex_hostname,
            devices,
            host_keys,
            observed_at=utc_now(),
        )
    except base.ProvisioningError:
        raise
    except Exception as exc:
        raise base.ProvisioningError(
            "post-cutover QFX attachment discovery failed: %s" % exc
        )
    finally:
        for dev in reversed(opened):
            try:
                dev.close()
            except Exception:
                pass

    _print_discovery(discovery)
    if discovery["result"] != "PASS":
        raise base.ProvisioningError(
            "QFX attachment discovery failed; no attachment artifact was created"
        )

    print(
        "\nThis observation proves the post-cutover physical port and existing AE "
        "on both QFXs. It does not authorize QFX or EX4400 writes."
    )
    answer = input(
        "Bind exactly this QFX attachment to migration %s? [y/N]: "
        % args.migration_id
    ).strip().lower()
    if answer not in ("y", "yes"):
        print("QFX attachment was not approved; no attachment artifact created.")
        return 1

    artifact = build_attachment_artifact(
        args.migration_id,
        selected["plan"]["plan_id"],
        selected["plan_digest"],
        policy["site_policy_id"],
        sha256_file(paths["site_policy"]),
        discovery,
        approved_at=utc_now(),
    )
    destination, artifact, action = write_attachment(migration_root, artifact)
    print("\nQFX attachment: %s (%s)" % (artifact["attachment_id"], action))
    print("  Physical interface: %s" % artifact["devices"][0]["physical_interface"])
    print("  AE: %s" % artifact["devices"][0]["ae_interface"])
    print("  Record: %s" % (destination / "attachment.json"))
    print("  QFX writes performed: no")
    print("  EX4400 writes performed: no")
    return 0
