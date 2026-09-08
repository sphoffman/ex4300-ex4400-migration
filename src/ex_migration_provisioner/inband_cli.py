from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes, sha256_file, utc_now

from . import cli_base as base
from .inband import (
    build_validation,
    choose_qfx_transaction,
    pinned_fingerprint,
    planned_management_ip,
    run_lab_probe,
    validate_environment_profile,
    write_validation,
)


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner validate-inband",
        description=(
            "POST-CUTOVER READ ONLY: prove that the approved EX4400 management IP is "
            "reachable through the in-band path and resolves to the SSH identity pinned "
            "during bootstrap. Lab profiles use a designated remote probe; production "
            "profiles connect directly with NETCONF."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument(
        "--environment-profile",
        type=Path,
        default=Path("config/environment.lab.json"),
    )
    parser.add_argument("--identity-id")
    parser.add_argument("--qfx-transaction-id")
    parser.add_argument("--probe-password-env")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    return parser


def _secret_from_env_or_prompt(env_name, prompt):
    if env_name:
        value = os.environ.get(env_name)
        if value is None:
            raise base.ProvisioningError("environment variable %s is not set" % env_name)
        return value
    return getpass.getpass(prompt)


def _member_identity(members):
    return sorted(
        [
            (
                int(item.get("member_id", -1)),
                str(item.get("serial_number") or ""),
                str(item.get("model") or "").lower(),
            )
            for item in members
        ]
    )


def _run_direct_netconf(args, profile, approved_plan, identity, management_ip, expected_fingerprint):
    validation = profile["inband_validation"]
    port = int(validation.get("target_port", 830))
    observed_fingerprint = base.ssh_host_key_fingerprint(management_ip, port)
    if observed_fingerprint != expected_fingerprint:
        raise base.ProvisioningError(
            "in-band SSH fingerprint does not match the approved bootstrap identity"
        )

    username = args.username or input("EX4400 username: ").strip()
    if not username:
        raise base.ProvisioningError("EX4400 username must not be empty")
    password = _secret_from_env_or_prompt(args.password_env, "EX4400 password: ")

    from jnpr.junos import Device

    dev = Device(
        host=management_ip,
        user=username,
        passwd=password,
        port=port,
        gather_facts=True,
    )
    try:
        dev.open(auto_probe=10, hostkey_verify=False)
        observed = base.observe_ex4400_identity(
            dev,
            management_ip,
            port,
            observed_fingerprint,
        )
    except base.ProvisioningError:
        raise
    except Exception as exc:
        raise base.ProvisioningError(
            "direct in-band NETCONF validation failed: %s" % exc
        )
    finally:
        try:
            dev.close()
        except Exception:
            pass

    expected_device = identity.get("observed", {}).get("device", {})
    observed_device = observed.get("device", {})
    expected_hostname = str(
        approved_plan.get("template_variables", {}).get("new_hostname") or ""
    )
    checks = {
        "ssh_fingerprint_matches_pinned_identity": observed_fingerprint == expected_fingerprint,
        "hostname_matches_approved_plan": observed_device.get("hostname") == expected_hostname,
        "model_matches_pinned_identity": str(observed_device.get("model") or "").lower()
        == str(expected_device.get("model") or "").lower(),
        "serial_matches_pinned_identity": str(observed_device.get("serial_number") or "")
        == str(expected_device.get("serial_number") or ""),
        "vc_members_match_pinned_identity": _member_identity(observed_device.get("members", []))
        == _member_identity(expected_device.get("members", [])),
    }
    if not all(checks.values()):
        failed = ", ".join(name for name, passed in checks.items() if not passed)
        raise base.ProvisioningError(
            "direct in-band NETCONF reached a device but identity validation failed: %s"
            % failed
        )

    return {
        "method": "direct-netconf",
        "target": {
            "management_ip": management_ip,
            "port": port,
        },
        "tcp_reachable": True,
        "netconf_opened": True,
        "observed_ed25519_fingerprint": observed_fingerprint,
        "expected_ed25519_fingerprint": expected_fingerprint,
        "fingerprint_match": True,
        "identity_checks": checks,
        "result": "PASS",
    }


def run(argv):
    args = _parser().parse_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id

    selected_plan = base.choose_approved_plan(migration_root)
    selected_identity = base.choose_identity(migration_root, args.identity_id)
    selected_qfx = choose_qfx_transaction(migration_root, args.qfx_transaction_id)

    if not args.environment_profile.is_file():
        raise base.ProvisioningError(
            "environment profile is missing: %s" % args.environment_profile
        )
    profile = validate_environment_profile(base.read_json(args.environment_profile))
    profile_digest = sha256_file(args.environment_profile)

    identity = selected_identity["identity"]
    identity_digest = sha256_bytes(canonical_bytes(identity))
    expected_fingerprint = pinned_fingerprint(identity)
    management_ip = planned_management_ip(selected_plan["plan"])

    mode = profile["inband_validation"]["mode"]
    if mode == "lab-probe":
        password = _secret_from_env_or_prompt(
            args.probe_password_env,
            "Lab probe password for %s@%s: "
            % (
                profile["inband_validation"]["probe"]["username"],
                profile["inband_validation"]["probe"]["host"],
            ),
        )
        evidence = run_lab_probe(
            profile,
            management_ip,
            expected_fingerprint,
            password,
        )
        if evidence["result"] != "PASS":
            raise base.ProvisioningError(
                "lab probe reached the management service but the SSH identity did not match"
            )
    elif mode == "direct-netconf":
        evidence = _run_direct_netconf(
            args,
            profile,
            selected_plan["plan"],
            identity,
            management_ip,
            expected_fingerprint,
        )
    else:
        raise base.ProvisioningError("unsupported in-band validation mode")

    value = build_validation(
        args.migration_id,
        identity,
        identity_digest,
        selected_qfx["transaction"],
        sha256_file(selected_qfx["transaction_path"]),
        profile,
        profile_digest,
        selected_plan["plan_digest"],
        evidence,
        created_at=utc_now(),
    )
    destination, value, action = write_validation(migration_root, value)

    print("\nPost-cutover in-band management validation")
    print("  Method: %s" % evidence["method"])
    print("  QFX transaction: %s" % selected_qfx["transaction"]["transaction_id"])
    if evidence["method"] == "lab-probe":
        print(
            "  Probe: %s@%s:%s"
            % (
                evidence["probe"]["username"],
                evidence["probe"]["host"],
                evidence["probe"]["port"],
            )
        )
    print(
        "  Target: %s:%s"
        % (evidence["target"]["management_ip"], evidence["target"]["port"])
    )
    print("  TCP/NETCONF transport: PASS")
    print("  Observed ED25519: %s" % evidence["observed_ed25519_fingerprint"])
    print("  Pinned ED25519:   %s" % evidence["expected_ed25519_fingerprint"])
    print("  SSH identity match: PASS")
    if evidence["method"] == "direct-netconf":
        print("  EX4400 chassis/VC identity: PASS")
    print("  Result: PASS")
    print("\nIn-band validation: %s (%s)" % (value["validation_id"], action))
    print("  Record: %s" % (destination / "validation.json"))
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
