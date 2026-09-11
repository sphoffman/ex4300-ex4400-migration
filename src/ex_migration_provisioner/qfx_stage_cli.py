from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ex_migration_analyzer.core import sha256_bytes, sha256_file, utc_now

from . import cli_base as base
from .prestage import validate_pre_cutover_site_policy
from .qfx_stage import (
    build_qfx_vlan_plan,
    choose_attachment,
    write_qfx_vlan_plan,
)
from .qfx_transaction import (
    build_transaction,
    persist_transaction,
    validate_post_commit_pair,
)


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner stage-qfx",
        description=(
            "POST-CUTOVER: revalidate the approved QFX attachment, derive only the "
            "production VLANs required by approved endpoint/voice intent, display the "
            "exact dual-QFX candidate diffs, and after one operator approval apply them "
            "as a coordinated commit-confirmed transaction."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--site-policy", type=Path)
    parser.add_argument("--attachment-id")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--confirm-minutes", type=int, default=10)
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="stop after creating/displaying the immutable read-only QFX VLAN plan",
    )
    parser.add_argument(
        "--no-host-key-check",
        action="store_true",
        help="LAB ONLY: disable NETCONF known-host verification; attachment-pinned SSH fingerprints are still checked",
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


def _transaction_device(transaction, role):
    for item in transaction["devices"]:
        if item["role"] == role:
            return item
    raise base.ProvisioningError("transaction is missing QFX role %s" % role)


def _normalize_diff(value):
    text = str(value or "")
    return text if not text or text.endswith("\n") else text + "\n"


def _inverse_statements(plan_device):
    result = []
    for statement in plan_device.get("statements", []):
        if statement.startswith("set "):
            result.append("delete " + statement[4:])
        elif statement.startswith("delete "):
            result.append("set " + statement[7:])
        else:
            raise base.ProvisioningError(
                "cannot derive compensating rollback for unsupported QFX statement"
            )
    return result


def _rollback_pair(
    configs,
    qfx_plan,
    committed_roles,
    final_confirmed_roles,
    transaction,
    migration_root,
    candidate_diffs,
):
    errors = []
    by_role = {item["role"]: item for item in qfx_plan["devices"]}
    for role in ("qfx-b", "qfx-a"):
        if role not in configs:
            continue
        cu = configs[role]
        try:
            if role in final_confirmed_roles:
                payload = "\n".join(_inverse_statements(by_role[role])) + "\n"
                cu.load(payload, format="set", merge=True)
                if cu.commit_check() is not True:
                    raise base.ProvisioningError(
                        "compensating rollback commit-check failed on %s" % role
                    )
                if cu.commit(
                    comment="Compensating rollback EX migration %s QFX transaction %s"
                    % (qfx_plan["migration_id"], transaction["transaction_id"]),
                    timeout=120,
                ) is not True:
                    raise base.ProvisioningError(
                        "compensating rollback commit failed on %s" % role
                    )
                _transaction_device(transaction, role)["commit_status"] = "COMPENSATING_ROLLBACK_COMMITTED"
            elif role in committed_roles:
                cu.rollback(rb_id=1)
                if cu.commit(
                    comment="Rollback EX migration %s QFX transaction %s"
                    % (qfx_plan["migration_id"], transaction["transaction_id"]),
                    timeout=120,
                ) is not True:
                    raise base.ProvisioningError("rollback commit failed on %s" % role)
                _transaction_device(transaction, role)["commit_status"] = "ROLLED_BACK"
            else:
                cu.rollback()
                _transaction_device(transaction, role)["commit_status"] = "CANDIDATE_ROLLED_BACK"
        except Exception as exc:
            errors.append("%s: %s" % (role, exc))
            try:
                _transaction_device(transaction, role)["commit_status"] = "ROLLBACK_FAILED"
            except Exception:
                pass

    transaction["status"] = "ROLLED_BACK" if not errors else "ROLLBACK_INCOMPLETE"
    transaction["rollback_at"] = utc_now()
    if errors:
        transaction["rollback_errors"] = errors
    persist_transaction(migration_root, transaction, candidate_diffs)
    return errors


def _display_candidate_diffs(candidate_diffs):
    print("\nCoordinated QFX candidate diffs")
    for role in ("qfx-a", "qfx-b"):
        text = candidate_diffs[role]
        print("\n  %s SHA256: %s" % (
            role,
            sha256_bytes(text.encode("utf-8")),
        ))
        print(text.rstrip())
    print("\n  Commit check: PASS on both QFXs")


def run(argv):
    args = _parser().parse_args(argv)
    if args.confirm_minutes < 1:
        raise base.ProvisioningError("--confirm-minutes must be at least 1")

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
        raise base.ProvisioningError(
            "--no-host-key-check is permitted only by a lab QFX site policy"
        )
    if not args.plan_only and policy.get("environment") != "lab":
        raise base.ProvisioningError(
            "coordinated live QFX writes are currently restricted to LAB_ONLY site policy"
        )

    username, password = base._credentials(args, "QFX")

    from jnpr.junos import Device

    devices = {}
    host_keys = {}
    opened = []
    configs = {}
    locked_roles = []
    candidate_diffs = {}
    transaction = None
    committed_roles = []
    final_confirmed_roles = []

    try:
        for device_policy in policy["qfx_pair"]:
            role = device_policy["role"]
            address = device_policy["management_address"]
            print("Connecting to %s at %s..." % (device_policy["expected_hostname"], address))
            host_keys[role] = base.ssh_host_key_fingerprint(address, args.port)
            dev = Device(
                host=address,
                user=username,
                passwd=password,
                port=args.port,
                gather_facts=True,
            )
            dev.open(auto_probe=10, hostkey_verify=not args.no_host_key_check)
            # PyEZ defaults ordinary RPCs to 30 seconds. QFX/virtual PTX
            # configuration and rollback RPCs can legitimately exceed that even
            # when explicit commit() calls use a longer timeout.
            dev.timeout = 120
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
        _print_plan(value)
        if value["result"] != "PASS":
            raise base.ProvisioningError(
                "QFX VLAN plan failed validation; no plan artifact was created"
            )

        destination, value, action = write_qfx_vlan_plan(migration_root, value)
        print("\nQFX VLAN plan: %s (%s)" % (value["qfx_plan_id"], action))
        print("  Plan: %s" % (destination / "plan.json"))
        if args.plan_only:
            print("  QFX writes performed: no (--plan-only)")
            print("  EX4400 writes performed: no")
            return 0

        from jnpr.junos.utils.config import Config

        for role in ("qfx-a", "qfx-b"):
            cu = Config(devices[role])
            cu.lock()
            configs[role] = cu
            locked_roles.append(role)
            if cu.diff():
                raise base.ProvisioningError(
                    "%s candidate already contains uncommitted changes; refusing to merge migration changes"
                    % role
                )

        # Revalidate the immutable attachment and plan again after both candidate
        # databases are locked. A topology/config change between observation and
        # lock therefore cannot be silently committed.
        locked_value = build_qfx_vlan_plan(
            args.migration_id,
            selected_plan["plan"],
            selected_plan["plan_digest"],
            selected_attachment["attachment"],
            sha256_file(selected_attachment["attachment_path"]),
            policy,
            sha256_file(paths["site_policy"]),
            devices,
            host_keys,
            created_at=value["created_at"],
        )
        if locked_value["result"] != "PASS" or locked_value["qfx_plan_id"] != value["qfx_plan_id"]:
            raise base.ProvisioningError(
                "QFX attachment/VLAN plan changed after locks were acquired; refusing to write"
            )

        plan_by_role = {item["role"]: item for item in value["devices"]}
        for role in ("qfx-a", "qfx-b"):
            payload = "\n".join(plan_by_role[role]["statements"]) + "\n"
            configs[role].load(payload, format="set", merge=True)

        for role in ("qfx-a", "qfx-b"):
            if configs[role].commit_check() is not True:
                raise base.ProvisioningError(
                    "%s QFX commit-check did not return PASS" % role
                )
            candidate_diffs[role] = _normalize_diff(configs[role].diff())
            if not candidate_diffs[role]:
                raise base.ProvisioningError(
                    "%s produced no candidate diff even though the approved attachment still showed only the migration baseline"
                    % role
                )

        if candidate_diffs["qfx-a"] != candidate_diffs["qfx-b"]:
            raise base.ProvisioningError(
                "QFX candidate diffs are not symmetric; refusing coordinated commit"
            )

        _display_candidate_diffs(candidate_diffs)
        answer = input(
            "\nApprove exactly these candidate diffs for commit confirmed on BOTH QFXs? [y/N]: "
        ).strip().lower()
        if answer not in ("y", "yes"):
            for role in reversed(locked_roles):
                configs[role].rollback()
            print("QFX candidate diffs were not approved; no commit was performed.")
            return 1

        transaction = build_transaction(
            value,
            candidate_diffs,
            approved_at=utc_now(),
            confirm_minutes=args.confirm_minutes,
        )
        tx_dir = persist_transaction(migration_root, transaction, candidate_diffs)

        for role in ("qfx-a", "qfx-b"):
            if configs[role].commit(
                confirm=args.confirm_minutes,
                comment="EX migration %s QFX stage %s"
                % (args.migration_id, transaction["transaction_id"]),
                timeout=120,
            ) is not True:
                raise base.ProvisioningError(
                    "%s commit confirmed did not return success" % role
                )
            committed_roles.append(role)
            _transaction_device(transaction, role)["commit_status"] = "CONFIRMED_PENDING_VALIDATION"
            transaction["status"] = "COMMIT_CONFIRMED_PENDING_VALIDATION"
            persist_transaction(migration_root, transaction, candidate_diffs)

        attachment_by_role = {
            item["role"]: item
            for item in selected_attachment["attachment"]["devices"]
        }
        for role in ("qfx-a", "qfx-b"):
            current_key = base.ssh_host_key_fingerprint(
                plan_by_role[role]["management_address"], args.port
            )
            if current_key != attachment_by_role[role]["ssh_host_key_sha256"]:
                raise base.ProvisioningError(
                    "%s SSH host key changed after commit confirmed" % role
                )

        validation = validate_post_commit_pair(
            devices,
            value,
            selected_attachment["attachment"]["expected_ex_hostname"],
        )
        transaction["validation"] = validation
        if validation["result"] != "PASS":
            raise base.ProvisioningError(
                "post-commit QFX validation failed on one or both devices"
            )
        transaction["status"] = "VALIDATED_PENDING_FINAL_CONFIRMATION"
        persist_transaction(migration_root, transaction, candidate_diffs)

        for role in ("qfx-a", "qfx-b"):
            if configs[role].commit(
                comment="Confirm EX migration %s QFX stage %s"
                % (args.migration_id, transaction["transaction_id"]),
                timeout=120,
            ) is not True:
                raise base.ProvisioningError(
                    "%s final confirmation commit did not return success" % role
                )
            final_confirmed_roles.append(role)
            _transaction_device(transaction, role)["commit_status"] = "COMMITTED_AND_CONFIRMED"
            persist_transaction(migration_root, transaction, candidate_diffs)

        transaction["status"] = "COMMITTED_AND_CONFIRMED"
        transaction["confirmed_at"] = utc_now()
        persist_transaction(migration_root, transaction, candidate_diffs)

        print("\nCoordinated QFX VLAN transaction: PASS")
        print("  Transaction: %s" % transaction["transaction_id"])
        print("  QFX commit-check: PASS on both")
        print("  Commit-confirmed validation: PASS on both")
        print("  Final confirmation: PASS on both")
        print("  Record: %s" % (tx_dir / "transaction.json"))
        print("  EX4400 writes performed: no")
        return 0

    except base.ProvisioningError:
        if transaction is not None and committed_roles:
            rollback_errors = _rollback_pair(
                configs,
                value,
                committed_roles,
                final_confirmed_roles,
                transaction,
                migration_root,
                candidate_diffs,
            )
            if rollback_errors:
                raise base.ProvisioningError(
                    "QFX transaction failed and coordinated rollback was incomplete: %s"
                    % "; ".join(rollback_errors)
                )
        else:
            for role in reversed(locked_roles):
                try:
                    configs[role].rollback()
                except Exception:
                    pass
        raise
    except Exception as exc:
        if transaction is not None and committed_roles:
            rollback_errors = _rollback_pair(
                configs,
                value,
                committed_roles,
                final_confirmed_roles,
                transaction,
                migration_root,
                candidate_diffs,
            )
            suffix = ""
            if rollback_errors:
                suffix = "; rollback incomplete: %s" % "; ".join(rollback_errors)
            raise base.ProvisioningError(
                "coordinated QFX VLAN transaction failed: %s%s" % (exc, suffix)
            )
        for role in reversed(locked_roles):
            try:
                configs[role].rollback()
            except Exception:
                pass
        raise base.ProvisioningError(
            "coordinated QFX VLAN transaction failed: %s" % exc
        )
    finally:
        for role in reversed(locked_roles):
            try:
                configs[role].unlock()
            except Exception:
                pass
        for dev in reversed(opened):
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
