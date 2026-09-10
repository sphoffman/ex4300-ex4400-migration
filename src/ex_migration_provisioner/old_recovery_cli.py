from __future__ import annotations

import ipaddress
import re
import sys
from pathlib import Path

from ex_migration_analyzer.core import sha256_bytes, sha256_file, utc_now

from . import cli_base as base
from .old_recovery import (
    MGMT_INSTANCE,
    build_recovery_transaction,
    persist_recovery_transaction,
    recovery_statements,
)


def _parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner stage-old-recovery",
        description=(
            "PRE-CUTOVER: pre-stage the approved replacement OOB address on the old "
            "EX4300 Virtual Chassis VME interface in mgmt_junos. The replacement may still "
            "own the same OOB address while the two OOB paths remain physically isolated."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument("--identity-id")
    parser.add_argument("--management-interface", default="vme", help="old-switch logical OOB management interface; EX4300 VC default: vme")
    parser.add_argument("--transport-address", help="LAB ONLY: reachable transport for the old switch's current in-band management")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--confirm-minutes", type=int, default=10)
    parser.add_argument("--no-host-key-check", action="store_true", help="LAB ONLY: disable normal host-key verification on the current source path")
    return parser


def _site_environment(settings):
    path = Path(settings.get("qfx_site_policy", "config/qfx-site-policy.lab.json"))
    if not path.is_file():
        raise base.ProvisioningError("QFX site policy is missing: %s" % path)
    policy = base.read_json(path)
    environment = str(policy.get("environment") or "")
    if environment not in ("lab", "production"):
        raise base.ProvisioningError("QFX site policy environment must be lab or production")
    return environment


def _identity_oob_inputs(settings, migration_root, bootstrap_override, identity_id):
    paths = base._provisioning_paths(settings)
    if bootstrap_override:
        paths["bootstrap"] = bootstrap_override
    if not paths["bootstrap"].is_file():
        raise base.ProvisioningError("bootstrap profile is missing: %s" % paths["bootstrap"])

    selected_identity = base.choose_identity(migration_root, identity_id)
    identity = selected_identity["identity"]
    profile_digest = sha256_file(paths["bootstrap"])
    bound_digest = str(identity.get("bootstrap", {}).get("profile_digest") or "")
    if profile_digest != bound_digest:
        raise base.ProvisioningError(
            "approved bootstrap identity is stale: bootstrap profile digest changed; rerun identify before staging old-switch recovery"
        )

    oob = identity.get("observed", {}).get("oob_management", {})
    if not oob:
        raise base.ProvisioningError(
            "approved identity predates authoritative OOB management capture; rerun identify with --oob-address before staging old-switch recovery"
        )
    if str(oob.get("routing_instance") or "") != MGMT_INSTANCE:
        raise base.ProvisioningError("approved identity OOB management is not bound to mgmt_junos")
    try:
        recovery = ipaddress.ip_interface(str(oob.get("address") or ""))
        gateway = ipaddress.ip_address(str(oob.get("default_gateway") or ""))
    except ValueError as exc:
        raise base.ProvisioningError("approved identity has invalid OOB management data: %s" % exc)
    if recovery.version != 4 or gateway.version != 4:
        raise base.ProvisioningError("approved OOB recovery addressing must be IPv4")

    connection_ip = str(
        identity.get("observed", {}).get("connection", {}).get("address") or ""
    ).strip()
    if connection_ip and connection_ip != str(recovery.ip):
        raise base.ProvisioningError(
            "approved identity connection address does not match its authoritative OOB address"
        )

    return {
        "identity": identity,
        "identity_digest": sha256_file(selected_identity["identity_path"]),
        "profile_digest": profile_digest,
        "recovery_address": str(recovery),
        "recovery_ip": str(recovery.ip),
        "gateway": str(gateway),
    }


def _configured_hostname(dev):
    value = str(dev.facts.get("hostname") or "").strip()
    if not value:
        raise base.ProvisioningError("old-switch hostname could not be observed")
    return value


def _configuration_set(dev):
    return dev.cli("show configuration | display set", warning=False) or ""


def _master_default_lines(config_text):
    return sorted(
        line.strip()
        for line in str(config_text or "").splitlines()
        if re.match(r"^set routing-options static route (?:0\.0\.0\.0/0|default)\b", line.strip())
    )


def _validate_existing_mgmt_default(config_text, gateway):
    prefix = "set routing-instances %s routing-options static route 0.0.0.0/0 next-hop " % MGMT_INSTANCE
    existing = sorted(
        line.strip()[len(prefix):]
        for line in str(config_text or "").splitlines()
        if line.strip().startswith(prefix)
    )
    if existing and existing != [str(gateway)]:
        raise base.ProvisioningError(
            "existing mgmt_junos default route conflicts with approved OOB gateway %s: %s"
            % (gateway, ", ".join(existing))
        )


def _validate_recovery_config(dev, statements, master_defaults_before, interface, expected_address):
    text = _configuration_set(dev)
    configured = {line.strip() for line in str(text or "").splitlines() if line.strip()}
    missing = [statement for statement in statements if statement not in configured]
    if missing:
        raise base.ProvisioningError(
            "old-switch recovery configuration is incomplete: %s" % "; ".join(missing)
        )

    expected_vme = "set interfaces %s unit 0 family inet address %s" % (
        interface,
        str(ipaddress.ip_interface(str(expected_address))),
    )
    actual_vme = sorted(
        line for line in configured if line.startswith("set interfaces %s " % interface)
    )
    if actual_vme != [expected_vme]:
        raise base.ProvisioningError(
            "%s recovery configuration is not authoritative: expected only %s; found %s"
            % (interface, expected_vme, "; ".join(actual_vme) or "none")
        )

    if _master_default_lines(text) != master_defaults_before:
        raise base.ProvisioningError(
            "master routing-table default route changed during old-switch recovery staging"
        )
    return True


def run(argv):
    args = _parser().parse_args(argv)
    if args.confirm_minutes < 1:
        raise base.ProvisioningError("--confirm-minutes must be at least 1")
    if not (1 <= args.port <= 65535):
        raise base.ProvisioningError("invalid NETCONF port")
    if str(args.management_interface).strip() != "vme":
        raise base.ProvisioningError("EX4300 Virtual Chassis recovery must use vme")

    settings = base.load_settings(args.settings)
    environment = _site_environment(settings)
    if environment != "lab" and (args.transport_address or args.no_host_key_check):
        raise base.ProvisioningError("transport override and --no-host-key-check are permitted only by a lab site policy")

    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected = base.choose_approved_plan(migration_root)
    plan = selected["plan"]
    variables = plan.get("template_variables", {})
    expected_hostname = str(variables.get("old_hostname") or "").strip()
    management_ip = str(variables.get("management_ip") or "").strip()
    if not expected_hostname or not management_ip:
        raise base.ProvisioningError("approved plan is missing old hostname or management IP")

    oob = _identity_oob_inputs(settings, migration_root, args.bootstrap, args.identity_id)
    if oob["recovery_ip"] == management_ip:
        raise base.ProvisioningError("approved OOB IP must differ from the production management IP")

    print("\nOld-switch recovery pre-stage")
    print("  Approved replacement identity: %s" % oob["identity"].get("identity_id"))
    print("  OOB address inherited from identify: %s" % oob["recovery_address"])
    print("  mgmt_junos default inherited from identify: %s" % oob["gateway"])
    print("  Destination: vme.0 in %s" % MGMT_INSTANCE)
    print("  VME policy: replace entire existing interface with approved recovery state")
    print("  Replacement EX4400 may still own %s before cutover." % oob["recovery_ip"])
    print("  Safety boundary: old/new OOB interfaces remain physically L2-isolated until the cable move.")

    source_transport = str(args.transport_address or management_ip)
    if environment == "lab":
        print("\nLAB ROLE HANDOFF")
        print("  This lab may reuse one device for both replacement EX4400 and old EX4300 roles.")
        print("  Change the shared lab device back to the approved old EX4300 configuration now.")
        print("  Expected old-switch hostname: %s" % expected_hostname)
        print("  Transport after role change: %s" % source_transport)
        answer = input("\nContinue after the lab device is presenting the old EX4300 role? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            print("Old-switch recovery paused for lab role change; no connection or write attempted.")
            return 1

    statements = recovery_statements(
        args.management_interface,
        oob["recovery_address"],
        oob["gateway"],
    )
    username, password = base._credentials(args, "Old EX4300")
    source_fingerprint = base.ssh_host_key_fingerprint(source_transport, args.port)

    from jnpr.junos import Device
    from jnpr.junos.utils.config import Config

    dev = Device(
        host=source_transport,
        user=username,
        passwd=password,
        port=args.port,
        gather_facts=True,
    )
    cu = None
    locked = False
    commit_confirmed_started = False
    transaction = None
    candidate_diff = ""
    try:
        print("Connecting to old EX4300 at %s:%s..." % (source_transport, args.port))
        dev.open(auto_probe=10, hostkey_verify=not args.no_host_key_check)
        observed_hostname = _configured_hostname(dev)
        if observed_hostname.lower() != expected_hostname.lower():
            raise base.ProvisioningError(
                "old-switch hostname %r does not match approved source hostname %r"
                % (observed_hostname, expected_hostname)
            )

        pre_config = _configuration_set(dev)
        pre_lines = {line.strip() for line in str(pre_config).splitlines() if line.strip()}
        master_defaults_before = _master_default_lines(pre_config)
        _validate_existing_mgmt_default(pre_config, oob["gateway"])

        interface_prefix = "set interfaces %s " % args.management_interface
        interface_exists = any(line.startswith(interface_prefix) for line in pre_lines)
        payload_lines = []
        if interface_exists:
            payload_lines.append("delete interfaces %s" % args.management_interface)
        payload_lines.extend(statements)
        payload = "\n".join(payload_lines) + "\n"

        print("\nRequired recovery state")
        if interface_exists:
            print("  [authoritative reset] delete interfaces %s" % args.management_interface)
        else:
            print("  [authoritative reset] interfaces %s absent; no delete required" % args.management_interface)
        for statement in statements:
            if statement.startswith("set interfaces %s " % args.management_interface):
                state = "authoritative set"
            else:
                state = "already present" if statement in pre_lines else "candidate addition"
            print("  [%s] %s" % (state, statement))

        cu = Config(dev)
        cu.lock()
        locked = True
        if cu.diff():
            raise base.ProvisioningError("old EX4300 candidate already contains uncommitted changes")
        cu.load(payload, format="set", merge=True)
        if cu.commit_check() is not True:
            raise base.ProvisioningError("old-switch recovery commit-check did not return PASS")
        candidate_diff = str(cu.diff() or "")

        print("\nOld EX4300 recovery intent")
        print("  Approved source hostname: %s" % expected_hostname)
        print("  Existing production management: %s (preserved)" % management_ip)
        print("  Recovery interface: %s.0 (authoritatively replaced)" % args.management_interface)
        print("  Recovery routing instance: %s" % MGMT_INSTANCE)
        print("  Recovery address: %s" % oob["recovery_address"])
        print("  Recovery default: 0.0.0.0/0 -> %s (%s only)" % (oob["gateway"], MGMT_INSTANCE))
        print("  Master routing-table default changed: no")
        print("  Post-cable recovery verification: optional read-only diagnostic")

        def new_transaction(diff):
            return build_recovery_transaction(
                args.migration_id,
                plan,
                selected["plan_digest"],
                selected["approval_digest"],
                environment,
                management_ip,
                source_transport,
                args.management_interface,
                oob["recovery_address"],
                oob["gateway"],
                source_fingerprint,
                diff,
                utc_now(),
                args.confirm_minutes,
                bootstrap_identity_id=oob["identity"].get("identity_id"),
                bootstrap_identity_digest=oob["identity_digest"],
                bootstrap_profile_digest=oob["profile_digest"],
                master_defaults_before=master_defaults_before,
            )

        if not candidate_diff:
            print("  Recovery configuration is already authoritative; validating committed state.")
            _validate_recovery_config(
                dev,
                statements,
                master_defaults_before,
                args.management_interface,
                oob["recovery_address"],
            )
            transaction = new_transaction("")
            transaction["commit"] = {
                "status": "ALREADY_PRESENT_VALIDATED",
                "confirmed": True,
                "confirmed_at": utc_now(),
            }
            transaction["validation"] = {
                "result": "PASS",
                "validated_at": utc_now(),
                "recovery_path_verified": False,
                "checks": [
                    "APPROVED_SOURCE_HOSTNAME_MATCH",
                    "APPROVED_IDENTITY_OOB_LINEAGE_MATCH",
                    "MGMT_JUNOS_ENABLED",
                    "VME_AUTHORITATIVE_RECOVERY_STATE",
                    "RECOVERY_CONFIGURATION_PRESENT",
                    "MGMT_JUNOS_DEFAULT_PRESENT",
                    "MASTER_DEFAULT_ROUTE_UNCHANGED",
                ],
                "warnings": ["POST_CABLE_RECOVERY_VERIFICATION_AVAILABLE"],
            }
            directory = persist_recovery_transaction(migration_root, transaction, "")
            print("\nOld-switch recovery pre-stage: PASS")
            print("  Recovery path verified now: no (optional after cable move)")
            print("  Record: %s" % (directory / "transaction.json"))
            return 0

        print("\nCandidate SHA256: %s" % sha256_bytes(candidate_diff.encode("utf-8")))
        print(candidate_diff.rstrip())
        answer = input("\nApprove exactly this old-switch recovery candidate for commit confirmed? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            cu.rollback()
            print("Old-switch recovery candidate was not approved; no commit was performed.")
            return 1

        transaction = new_transaction(candidate_diff)
        directory = persist_recovery_transaction(migration_root, transaction, candidate_diff)

        if cu.commit(
            confirm=args.confirm_minutes,
            comment="EX migration %s old-switch recovery %s" % (args.migration_id, transaction["transaction_id"]),
            timeout=120,
        ) is not True:
            raise base.ProvisioningError("old-switch recovery commit confirmed did not return success")
        commit_confirmed_started = True
        transaction["commit"]["status"] = "CONFIRMED_PENDING_INBAND_VALIDATION"
        transaction["commit"]["commit_confirmed_at"] = utc_now()
        persist_recovery_transaction(migration_root, transaction, candidate_diff)

        _validate_recovery_config(
            dev,
            statements,
            master_defaults_before,
            args.management_interface,
            oob["recovery_address"],
        )
        transaction["validation"] = {
            "result": "PASS",
            "validated_at": utc_now(),
            "recovery_path_verified": False,
            "checks": [
                "APPROVED_SOURCE_HOSTNAME_MATCH",
                "APPROVED_IDENTITY_OOB_LINEAGE_MATCH",
                "MGMT_JUNOS_ENABLED",
                "VME_AUTHORITATIVE_RECOVERY_STATE",
                "RECOVERY_CONFIGURATION_PRESENT",
                "MGMT_JUNOS_DEFAULT_PRESENT",
                "MASTER_DEFAULT_ROUTE_UNCHANGED",
            ],
            "warnings": ["POST_CABLE_RECOVERY_VERIFICATION_AVAILABLE"],
        }
        transaction["commit"]["status"] = "VALIDATED_PENDING_FINAL_CONFIRMATION"
        persist_recovery_transaction(migration_root, transaction, candidate_diff)

        if cu.commit(
            comment="Confirm EX migration %s old-switch recovery %s" % (args.migration_id, transaction["transaction_id"]),
            timeout=120,
        ) is not True:
            raise base.ProvisioningError("final old-switch recovery confirmation did not return success")
        commit_confirmed_started = False
        transaction["commit"]["status"] = "COMMITTED_AND_CONFIRMED"
        transaction["commit"]["confirmed"] = True
        transaction["commit"]["confirmed_at"] = utc_now()
        persist_recovery_transaction(migration_root, transaction, candidate_diff)

        print("\nOld-switch recovery pre-stage: PASS")
        print("  VME configuration replaced with approved recovery state: yes")
        print("  Existing in-band management changed: no")
        print("  Master routing-table default changed: no")
        print("  Recovery path verified now: no (optional after cable move)")
        print("  Final confirmation: PASS")
        print("  Record: %s" % (directory / "transaction.json"))
        return 0

    except base.ProvisioningError as exc:
        if transaction is not None and commit_confirmed_started and cu is not None:
            transaction["validation"] = {"result": "FAIL", "validated_at": utc_now(), "error": str(exc), "checks": []}
            try:
                cu.rollback(rb_id=1)
                if cu.commit(
                    comment="Rollback failed EX migration %s old-switch recovery %s" % (args.migration_id, transaction["transaction_id"]),
                    timeout=120,
                ) is not True:
                    raise base.ProvisioningError("explicit old-switch recovery rollback did not return success")
                transaction["commit"]["status"] = "ROLLED_BACK_AFTER_VALIDATION_FAILURE"
                transaction["commit"]["rollback_at"] = utc_now()
                commit_confirmed_started = False
            except Exception as rollback_exc:
                transaction["commit"]["status"] = "AUTO_ROLLBACK_PENDING"
                transaction["commit"]["rollback_error"] = str(rollback_exc)
            persist_recovery_transaction(migration_root, transaction, candidate_diff)
            raise base.ProvisioningError(
                "old-switch recovery failed after commit confirmed; rollback status %s: %s"
                % (transaction["commit"]["status"], exc)
            )
        if locked and cu is not None and transaction is None:
            try:
                cu.rollback()
            except Exception:
                pass
        raise
    except Exception as exc:
        if locked and cu is not None and not commit_confirmed_started:
            try:
                cu.rollback()
            except Exception:
                pass
        raise base.ProvisioningError("old-switch recovery staging failed: %s" % exc)
    finally:
        if locked and cu is not None:
            try:
                cu.unlock()
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
