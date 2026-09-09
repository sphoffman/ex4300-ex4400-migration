from __future__ import annotations

import re
import sys
from pathlib import Path

from ex_migration_analyzer.core import sha256_bytes, utc_now

from . import cli_base as base
from .old_recovery import (
    MGMT_INSTANCE,
    build_recovery_verification,
    choose_recovery_transaction,
    persist_recovery_verification,
    recovery_statements,
)


def _parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner verify-old-recovery",
        description=(
            "POST-CABLE-MOVE diagnostic: verify that the old EX4300 VC is reachable through "
            "its pre-staged OOB recovery address. Failure is diagnostic only and does not "
            "modify either switch."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--recovery-transaction-id")
    parser.add_argument("--transport-address", help="LAB ONLY: reachable transport used instead of the logical recovery IP")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    return parser


def _site_environment(settings):
    path = Path(settings.get("qfx_site_policy", "config/qfx-site-policy.lab.json"))
    if not path.is_file():
        raise base.ProvisioningError("QFX site policy is missing: %s" % path)
    value = base.read_json(path)
    environment = str(value.get("environment") or "")
    if environment not in ("lab", "production"):
        raise base.ProvisioningError("QFX site policy environment must be lab or production")
    return environment


def _master_default_lines(config_text):
    return sorted(
        line.strip()
        for line in str(config_text or "").splitlines()
        if re.match(r"^set routing-options static route (?:0\.0\.0\.0/0|default)\b", line.strip())
    )


def _configuration_set(dev):
    return dev.cli("show configuration | display set", warning=False) or ""


def _not_reachable(target, exc):
    print("\nOld-switch recovery verification: NOT REACHABLE")
    print("  Target: %s" % target)
    print("  No configuration changes were attempted.")
    print("  First recovery action: verify/move the physical OOB recovery cabling so the old EX4300 VC is connected to the bootstrap OOB network.")
    print("  Expected logical recovery address: %s" % target)
    print("  Connection error: %s" % exc)
    return 1


def run(argv):
    args = _parser().parse_args(argv)
    if not (1 <= args.port <= 65535):
        raise base.ProvisioningError("invalid NETCONF port")

    settings = base.load_settings(args.settings)
    environment = _site_environment(settings)
    if environment != "lab" and args.transport_address:
        raise base.ProvisioningError("--transport-address is permitted only by a lab site policy")

    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected = choose_recovery_transaction(migration_root, args.recovery_transaction_id)
    tx = selected["transaction"]
    recovery = tx.get("recovery", {})
    logical = str(recovery.get("logical_address") or "").strip()
    if not logical:
        raise base.ProvisioningError("recovery transaction has no logical recovery address")
    target = str(args.transport_address or logical)

    expected_hostname = str(tx.get("source_identity", {}).get("configured_hostname") or "").strip()
    expected_fingerprint = str(tx.get("source_ssh_host_key_sha256") or "").strip()
    statements = recovery_statements(
        recovery.get("interface"),
        recovery.get("address"),
        recovery.get("gateway"),
    )
    master_defaults_before = sorted(tx.get("master_defaults_before") or [])

    username, password = base._credentials(args, "Old EX4300 recovery")

    try:
        fingerprint = base.ssh_host_key_fingerprint(target, args.port)
    except Exception as exc:
        return _not_reachable(logical, exc)
    if fingerprint != expected_fingerprint:
        raise base.ProvisioningError(
            "recovery target SSH host key does not match the old switch staged before cutover"
        )

    from jnpr.junos import Device

    dev = Device(
        host=target,
        user=username,
        passwd=password,
        port=args.port,
        gather_facts=True,
    )
    try:
        try:
            dev.open(auto_probe=10, hostkey_verify=False)
        except Exception as exc:
            return _not_reachable(logical, exc)

        hostname = str(dev.facts.get("hostname") or "").strip()
        if hostname.lower() != expected_hostname.lower():
            raise base.ProvisioningError(
                "recovery path reached hostname %r instead of staged old-switch hostname %r"
                % (hostname, expected_hostname)
            )

        config_text = _configuration_set(dev)
        configured = {line.strip() for line in str(config_text).splitlines() if line.strip()}
        missing = [statement for statement in statements if statement not in configured]
        if missing:
            raise base.ProvisioningError(
                "recovery path reached the expected old switch but recovery configuration is incomplete: %s"
                % "; ".join(missing)
            )
        if _master_default_lines(config_text) != master_defaults_before:
            raise base.ProvisioningError(
                "old-switch master routing-table default differs from the pre-cutover recovery transaction"
            )

        verification = build_recovery_verification(
            tx,
            selected["transaction_digest"],
            hostname,
            fingerprint,
            sha256_bytes(str(config_text).encode("utf-8")),
            utc_now(),
        )
        destination, verification, action = persist_recovery_verification(
            migration_root,
            verification,
        )

        print("\nOld-switch recovery verification: PASS")
        print("  Logical recovery address: %s" % logical)
        if target != logical:
            print("  Lab transport: %s:%s" % (target, args.port))
        print("  Hostname: %s" % hostname)
        print("  Routing instance: %s" % MGMT_INSTANCE)
        print("  Verification: %s (%s)" % (verification["verification_id"], action))
        print("  Record: %s" % (destination / "verification.json"))
        print("  Device writes performed: no")
        return 0
    finally:
        try:
            dev.close()
        except Exception:
            pass


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
