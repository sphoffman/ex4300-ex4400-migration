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
            "PRE-CUTOVER: pre-stage the approved replacement-bootstrap OOB address on the old "
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


def _bootstrap_inputs(settings, migration_root, bootstrap_override, identity_id):
    paths = base._provisioning_paths(settings)
    if bootstrap_override:
        paths["bootstrap"] = bootstrap_override
    if not paths["bootstrap"].is_file():
        raise base.ProvisioningError("bootstrap profile is missing: %s" % paths["bootstrap"])

    selected_identity = base.choose_identity(migration_root, identity_id)
    identity = selected_identity["identity"]
    profile = base.read_json(paths["bootstrap"])
    profile_digest = sha256_file(paths["bootstrap"])
    bound_digest = str(identity.get("bootstrap", {}).get("profile_digest") or "")
    if profile_digest != bound_digest:
        raise base.ProvisioningError(
            "approved bootstrap identity is stale: bootstrap profile digest changed; rerun identify before staging old-switch recovery"
        )

    connection = identity.get("observed", {}).get("connection", {})
    bound_ip = str(connection.get("address") or "").strip()
    profile_ip = str(profile.get("fxp0_management_ip") or "").strip()
    if not bound_ip or bound_ip != profile_ip:
        raise base.ProvisioningError(
            "approved bootstrap identity logical OOB address does not match the bound bootstrap profile"
        )
    try:
        prefix_length = int(profile.get("fxp0_prefix_length"))
        recovery = ipaddress.ip_interface("%s/%s" % (bound_ip, prefix_length))
        gateway = ipaddress.ip_address(str(profile.get("fxp0_management_gateway") or ""))
    except (TypeError, ValueError) as exc:
        raise base.ProvisioningError("bootstrap profile has invalid OOB addressing: %s" % exc)
    if recovery.version != 4 or gateway.version != 4:
        raise base.ProvisioningError("bootstrap OOB recovery addressing must be IPv4")
    if gateway not in recovery.network:
        raise base.ProvisioningError("bootstrap OOB gateway is not on the bootstrap OOB subnet")

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
            "existing mgmt_junos default route conflicts with bootstrap OOB gateway %s: %s"
            % (gateway, ", ".join(existing))
        )


def _validate_recovery_config(dev, statements, master_defaults_before):
    text = _configuration_set(dev)
    configured = {line.strip() for line in str(text).splitlines() if line.strip()}
    missing = [statement for statement in statements if statement not in configured]
    if missing:
        raise base.ProvisioningError(
            "old-switch recovery configuration is incomplete: %s" % "; ".join(missing)
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

    bootstrap = _bootstrap_inputs(settings, migration_root, args.bootstrap, args.identity_id)
    if bootstrap["recovery_ip"] == management_ip:
        raise base.ProvisioningError("bootstrap OOB IP must differ from the production management IP")

    print("\nOld-switch recovery pre-stage")
    print("  Approved replacement bootstrap identity: %s" % bootstrap["identity"].get("identity_id"))
    print("  OOB address pre-staged on old VC: %s" % bootstrap["recovery_address"])
    print("  OOB gateway: %s" % bootstrap["gateway"])
    print("  Destination: vme.0 in %s" % MGMT_INSTANCE)
    print("  Replacement EX4400 may still own %s before cutover." % bootstrap["recovery_ip"])
    print("  Safety boundary: old/new OOB interfaces remain physically L2-isolated until the cable move.")

    source_transport = str(args.transport_address or management_ip)
    statements = recovery_statements(
        args.management_interface,
        bootstrap["recovery_address"],
        bootstrap["gateway"],
    )
    payload = "\n".join(statements) + "\n"
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
        _validate_existing_mgmt_default(pre_config, bootstrap["gateway"])

        print("\nRequired recovery state")
        for statement in statements:
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
        print("  Recovery interface: %s.0" % args.management_interface)
        print("  Recovery routing instance: %s" % MGMT_INSTANCE)
        print("  Recovery address: %s" % bootstrap["recovery_address"])
        print("  Recovery default: 0.0.0.0/0 -> %s (%s only)" % (bootstrap["gateway"], MGMT_INSTANCE))
        print("  Master routing-table default changed: no")
        print("  Post-cable recovery verification: separate read-only diagnostic")

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
                bootstrap["recovery_address"],
                bootstrap["gateway"],
                source_fingerprint,
                diff,
                utc_now(),
                args.confirm_minutes,
                bootstrap_identity_id=bootstrap["identity"].get("identity_id"),
                bootstrap_identity_digest=bootstrap["identity_digest"],
                bootstrap_profile_digest=bootstrap["profile_digest"],
                master_defaults_before=master_defaults_before,
            )

        if not candidate_diff:
            print("  Recovery configuration is already present; validating committed state.")
            _validate_recovery_config(dev, statements, master_defaults_before)
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
                    "BOOTSTRAP_OOB_LINEAGE_MATCH",
                    "MGMT_JUNOS_ENABLED",
                    "RECOVERY_CONFIGURATION_PRESENT",
                    "MGMT_JUNOS_DEFAULT_PRESENT",
                    "MASTER_DEFAULT_ROUTE_UNCHANGED",
                ],
                "warnings": ["POST_CABLE_RECOVERY_VERIFICATION_PENDING"],
            }
            directory = persist_recovery_transaction(migration_root, transaction, "")
            print("\nOld-switch recovery pre-stage: PASS")
            print("  Recovery path verified now: no (physical cable has not moved)")
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

        _validate_recovery_config(dev, statements, master_defaults_before)
        transaction["validation"] = {
            "result": "PASS",
            "validated_at": utc_now(),
            "recovery_path_verified": False,
            "checks": [
                "APPROVED_SOURCE_HOSTNAME_MATCH",
                "BOOTSTRAP_OOB_LINEAGE_MATCH",
                "MGMT_JUNOS_ENABLED",
                "RECOVERY_CONFIGURATION_PRESENT",
                "MGMT_JUNOS_DEFAULT_PRESENT",
                "MASTER_DEFAULT_ROUTE_UNCHANGED",
            ],
            "warnings": ["POST_CABLE_RECOVERY_VERIFICATION_PENDING"],
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
        print("  Existing in-band management changed: no")
        print("  Master routing-table default changed: no")
        print("  Recovery path verified now: no (physical cable has not moved)")
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
