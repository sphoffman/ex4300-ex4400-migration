from __future__ import annotations

import argparse
import re
import shlex
import sys
from pathlib import Path

from ex_migration_analyzer.core import read_json, sha256_bytes, sha256_file, utc_now
from ex_migration_discovery.parsers import parse_mac_table_text

from . import cli_base as base
from .endpoint_stage import (
    build_correlation_artifact,
    build_endpoint_transaction,
    correlate_endpoint_intent,
    persist_endpoint_transaction,
    qfx_plan_for_transaction,
    resolve_postcutover_access,
    validate_postcutover_access,
    write_correlation,
)
from .inband import choose_qfx_transaction, planned_management_ip
from .prestage import choose_package_compat


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner activate-endpoints",
        description=(
            "POST-CUTOVER: connect to the replacement EX4400, correlate approved "
            "historical endpoint MACs to current edge ports, and apply only "
            "unambiguous descriptions/data-VLAN assignments using commit confirmed."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--environment", type=Path, default=Path("config/environment.lab.json"))
    parser.add_argument("--identity-id")
    parser.add_argument("--package-id")
    parser.add_argument("--qfx-transaction-id")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--confirm-minutes", type=int, default=10)
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="observe/correlate only; create no EX candidate and perform no write",
    )
    return parser


def _bind_lab_identity_transport(profile, identity):
    if profile.get("environment") != "lab":
        return profile
    access = profile.get("postcutover_ex_access") or {}
    if access.get("mode") != "transport-override":
        return profile

    connection = identity.get("observed", {}).get("connection", {})
    address = str(connection.get("address") or "").strip()
    transport = str(connection.get("transport_address") or address).strip()
    if not transport:
        raise base.ProvisioningError(
            "approved bootstrap identity has no pinned OOB connection address; rerun identify with --oob-address"
        )
    access["transport_address"] = transport
    profile["postcutover_ex_access"] = access
    return profile


def _member_identity(members):
    return [
        {
            "member_id": int(item["member_id"]),
            "serial_number": str(item["serial_number"]),
            "model": str(item["model"]),
        }
        for item in sorted(members, key=lambda value: int(value["member_id"]))
    ]


def _validate_postcutover_identity(current, identity, expected_hostname):
    bound = identity.get("observed", {})
    bound_connection = bound.get("connection", {})
    current_connection = current.get("connection", {})
    if current_connection.get("ssh_host_key_sha256") != bound_connection.get("ssh_host_key_sha256"):
        raise base.ProvisioningError("EX4400 SSH host key does not match the approved bootstrap identity")
    bound_device = bound.get("device", {})
    current_device = current.get("device", {})
    if current_device.get("hostname") != expected_hostname:
        raise base.ProvisioningError(
            "EX4400 hostname %r does not match approved target %r"
            % (current_device.get("hostname"), expected_hostname)
        )
    if str(current_device.get("model", "")).lower() != str(bound_device.get("model", "")).lower():
        raise base.ProvisioningError("EX4400 model does not match the approved bootstrap identity")
    if _member_identity(current_device.get("members", [])) != _member_identity(bound_device.get("members", [])):
        raise base.ProvisioningError("EX4400 virtual-chassis serial/model identity changed")
    return True


def _recovery_interface(identity):
    members = identity.get("observed", {}).get("device", {}).get("members", [])
    if not members:
        raise base.ProvisioningError("approved identity has no VC member inventory")
    highest = max(int(item["member_id"]) for item in members)
    return "ge-%d/0/47" % highest


def _canonical(line):
    try:
        return " ".join(shlex.split(str(line).strip(), comments=False, posix=True))
    except ValueError:
        return str(line).strip()


def _explicit_vlan_members(config_text, interface):
    pattern = re.compile(
        r"^set interfaces %s unit 0 family ethernet-switching vlan members (?P<name>\S+)$"
        % re.escape(interface)
    )
    values = []
    for raw in str(config_text or "").splitlines():
        match = pattern.match(raw.strip())
        if match:
            values.append(match.group("name"))
    return sorted(set(values))


def _interfaces_config_set(dev, database):
    options = {"format": "set"}
    if database == "committed":
        options["database"] = "committed"
    elif database != "candidate":
        raise base.ProvisioningError("unsupported configuration database %r" % database)
    reply = dev.rpc.get_config(
        filter_xml="interfaces",
        options=options,
        normalize=False,
    )
    return str(getattr(reply, "text", "") or "")


def _planned_config_rows(config_text, activated):
    configured = {
        _canonical(line)
        for line in str(config_text or "").splitlines()
        if line.strip()
    }
    rows = []
    hard_pass = True
    for item in activated:
        wanted = [_canonical(line) for line in item["statements"]]
        missing = [line for line in wanted if line not in configured]
        config_ok = not missing
        hard_pass = hard_pass and config_ok
        rows.append({
            "old_interface": item["old_interface"],
            "new_interface": item["new_interface"],
            "configuration_present": config_ok,
            "missing_statements": missing,
        })
    return hard_pass, rows


def _validate_preload_port_config(dev, activated):
    text = _interfaces_config_set(dev, "committed")
    for item in activated:
        interface = item["new_interface"]
        memberships = _explicit_vlan_members(text, interface)
        target = item["data_vlan_name"]
        unexpected = [name for name in memberships if name != target]
        if unexpected:
            raise base.ProvisioningError(
                "%s already has unexpected explicit VLAN membership(s): %s"
                % (interface, ", ".join(unexpected))
            )


def _validate_loaded_candidate(dev, activated):
    candidate_text = _interfaces_config_set(dev, "candidate")
    hard_ok, rows = _planned_config_rows(candidate_text, activated)
    if not hard_ok:
        missing = []
        for row in rows:
            missing.extend(row["missing_statements"])
        raise base.ProvisioningError(
            "EX4400 candidate is missing %d intended endpoint statement(s) after NETCONF load: %s"
            % (len(missing), "; ".join(missing[:5]))
        )
    return rows


def _print_correlation(value):
    correlation = value["correlation"]
    print("\nPost-cutover EX4400 endpoint correlation")
    print("  Logical target: %s:%s" % (
        value["access"]["logical_address"],
        value["access"]["port"],
    ))
    if value["access"]["transport_address"] != value["access"]["logical_address"]:
        print("  Lab transport: %s:%s" % (
            value["access"]["transport_address"],
            value["access"]["port"],
        ))
    print("  Unambiguous endpoint intents: %d" % len(correlation["activated"]))
    for item in correlation["activated"]:
        supporting = sorted(item["observed_support"])
        print(
            "    %s -> %s | VLAN %s (%s) | MAC evidence: %s"
            % (
                item["old_interface"],
                item["new_interface"],
                item["data_vlan_id"],
                item["data_vlan_name"],
                ", ".join(supporting),
            )
        )
        if item.get("description"):
            print("      description: %s" % item["description"])
    print("  Holds: %d" % len(correlation["holds"]))
    for item in correlation["holds"]:
        print("    %s: %s" % (item["old_interface"], item["reason"]))
    print("  Result: %s" % value["result"])


def _interface_up_from_terse(terse_text, interface):
    return bool(re.search(
        r"(?m)^%s(?:\.\d+)?\s+up\s+up(?:\s|$)" % re.escape(interface),
        str(terse_text or ""),
    ))


def _config_validation(dev, activated):
    config_text = _interfaces_config_set(dev, "committed")
    terse_text = dev.cli("show interfaces terse", warning=False) or ""
    hard_pass, config_rows = _planned_config_rows(config_text, activated)
    rows = []
    for row in config_rows:
        rows.append({
            "old_interface": row["old_interface"],
            "new_interface": row["new_interface"],
            "configuration_present": row["configuration_present"],
            "interface_up": _interface_up_from_terse(terse_text, row["new_interface"]),
        })
    return hard_pass, rows


def _mac_evidence(dev, activated):
    text = dev.cli("show ethernet-switching table extensive", warning=False) or ""
    observations = parse_mac_table_text(text, utc_now(), "post-commit-ex4400-mac-table")
    by_interface = {}
    for item in activated:
        expected = set(item["expected_macs"])
        observed = sorted({
            row.mac
            for row in observations
            if row.physical_interface == item["new_interface"] and row.mac in expected
        })
        by_interface[item["new_interface"]] = {
            "old_interface": item["old_interface"],
            "new_interface": item["new_interface"],
            "expected_macs": sorted(expected),
            "observed_expected_macs": observed,
            "mac_evidence_present": bool(observed),
        }
    return [by_interface[key] for key in sorted(by_interface)]


def run(argv):
    args = _parser().parse_args(argv)
    if args.confirm_minutes < 1:
        raise base.ProvisioningError("--confirm-minutes must be at least 1")

    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected_plan = base.choose_approved_plan(migration_root)
    selected_identity = base.choose_identity(migration_root, args.identity_id)
    selected_package = choose_package_compat(migration_root, args.package_id)
    package = selected_package["package"]
    if package.get("inputs", {}).get("plan_digest") != selected_plan["plan_digest"]:
        raise base.ProvisioningError("selected pre-stage package is bound to a different approved migration plan")

    qfx_selected = choose_qfx_transaction(migration_root, args.qfx_transaction_id)
    qfx_transaction = qfx_selected["transaction"]
    qfx_plan = qfx_plan_for_transaction(
        migration_root,
        qfx_transaction,
        selected_plan["plan_digest"],
    )

    profile = read_json(args.environment)
    profile = _bind_lab_identity_transport(profile, selected_identity["identity"])
    profile = validate_postcutover_access(profile)
    management_ip = planned_management_ip(selected_plan["plan"])
    access = resolve_postcutover_access(profile, management_ip)
    environment_digest = sha256_file(args.environment)

    variables = package.get("variables", {})
    management_vlan_id = int(variables.get("management_vlan_id"))
    voice_vlan_id = int(variables.get("voice_vlan_id"))
    recovery_vlan_id = int(variables.get("temporary_recovery_vlan_id"))
    prestage_access_vlan_id = variables.get("prestage_access_vlan_id")
    uplink_interfaces = variables.get("uplink_interfaces")
    if prestage_access_vlan_id is None or not isinstance(uplink_interfaces, list) or not uplink_interfaces:
        raise base.ProvisioningError(
            "selected pre-stage package predates the default holding-VLAN/uplink model; rerun prepare/render/run before endpoint activation"
        )
    prestage_access_vlan_id = int(prestage_access_vlan_id)
    recovery_interface = str(variables.get("recovery_interface") or _recovery_interface(selected_identity["identity"]))

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
    from jnpr.junos.utils.config import Config

    dev = Device(
        host=transport,
        user=username,
        passwd=password,
        port=port,
        gather_facts=True,
    )
    cu = None
    locked = False
    commit_confirmed_started = False
    transaction = None
    candidate_diff = ""
    try:
        print("Connecting to EX4400 at %s:%s..." % (transport, port))
        dev.open(auto_probe=10, hostkey_verify=False)
        current_identity = base.observe_ex4400_identity(
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
            current_identity,
            selected_identity["identity"],
            expected_hostname,
        )

        mac_text = dev.cli("show ethernet-switching table extensive", warning=False) or ""
        correlation = correlate_endpoint_intent(
            selected_plan["plan"],
            mac_text,
            recovery_interface,
            management_vlan_id,
            voice_vlan_id,
            recovery_vlan_id,
            observed_at=utc_now(),
            prestage_access_vlan_id=prestage_access_vlan_id,
            uplink_interfaces=uplink_interfaces,
        )
        value = build_correlation_artifact(
            args.migration_id,
            selected_plan["plan"],
            selected_plan["plan_digest"],
            selected_identity["identity"],
            sha256_file(selected_identity["identity_path"]),
            qfx_transaction,
            sha256_file(qfx_selected["transaction_path"]),
            qfx_plan["plan_digest"],
            environment_digest,
            access,
            correlation,
            mac_text,
            created_at=utc_now(),
        )
        correlation_dir, value, action = write_correlation(
            migration_root,
            value,
            mac_text,
        )
        _print_correlation(value)
        print("\nEndpoint correlation: %s (%s)" % (value["correlation_id"], action))
        print("  Record: %s" % (correlation_dir / "correlation.json"))

        if not correlation["activated"]:
            raise base.ProvisioningError(
                "no endpoint intent was safe to activate; resolve/observe held endpoints before writing"
            )
        if args.plan_only:
            print("  EX4400 writes performed: no (--plan-only)")
            print("  QFX writes performed: no")
            return 0

        _validate_preload_port_config(dev, correlation["activated"])
        cu = Config(dev)
        cu.lock()
        locked = True
        if cu.diff():
            raise base.ProvisioningError(
                "EX4400 candidate already contains uncommitted changes; refusing endpoint activation"
            )

        statements = []
        for item in correlation["activated"]:
            statements.extend(item["statements"])
        payload = "\n".join(statements) + "\n"
        cu.load(payload, format="set", merge=True)

        candidate_rows = _validate_loaded_candidate(dev, correlation["activated"])
        if cu.commit_check() is not True:
            raise base.ProvisioningError("EX4400 endpoint activation commit-check did not return PASS")
        raw_diff = cu.diff()
        if not raw_diff:
            print("\nEX4400 endpoint configuration is already present.")
            print("Candidate verification: PASS (%d endpoint intents)" % len(candidate_rows))
            print("No candidate diff exists; no commit was performed.")
            print("  Holds remaining: %d" % len(correlation["holds"]))
            return 0

        candidate_diff = str(raw_diff)
        print("\nEX4400 endpoint candidate diff")
        print("  SHA256: %s" % sha256_bytes(candidate_diff.encode("utf-8")))
        print("  Candidate verification: PASS (%d endpoint intents)" % len(candidate_rows))
        print("  Commit check: PASS")
        print("\n%s" % candidate_diff.rstrip())
        answer = input(
            "\nApprove exactly this endpoint candidate diff for commit confirmed? [y/N]: "
        ).strip().lower()
        if answer not in ("y", "yes"):
            cu.rollback()
            print("Endpoint candidate diff was not approved; no commit was performed.")
            return 1

        transaction = build_endpoint_transaction(
            value,
            candidate_diff,
            approved_at=utc_now(),
            confirm_minutes=args.confirm_minutes,
        )
        tx_dir = persist_endpoint_transaction(
            migration_root,
            transaction,
            candidate_diff,
        )

        if cu.commit(
            confirm=args.confirm_minutes,
            comment="EX migration %s endpoint activation %s"
            % (args.migration_id, transaction["transaction_id"]),
            timeout=120,
        ) is not True:
            raise base.ProvisioningError("EX4400 endpoint commit confirmed did not return success")
        commit_confirmed_started = True
        transaction["commit"]["status"] = "CONFIRMED_PENDING_VALIDATION"
        transaction["commit"]["commit_confirmed_at"] = utc_now()
        persist_endpoint_transaction(migration_root, transaction, candidate_diff)

        post_fingerprint = base.ssh_host_key_fingerprint(transport, port)
        if post_fingerprint != bound_fingerprint:
            raise base.ProvisioningError("EX4400 SSH host key changed after endpoint commit confirmed")
        try:
            dev.facts_refresh()
        except Exception:
            pass
        post_identity = base.observe_ex4400_identity(
            dev,
            management_ip,
            port,
            post_fingerprint,
            allow_vjunos_switch=access["allow_vjunos_switch"],
        )
        _validate_postcutover_identity(
            post_identity,
            selected_identity["identity"],
            expected_hostname,
        )
        hard_ok, config_rows = _config_validation(dev, correlation["activated"])
        if not hard_ok:
            raise base.ProvisioningError("post-commit endpoint configuration validation failed")
        endpoint_evidence = _mac_evidence(dev, correlation["activated"])
        transaction["validation"] = {
            "result": "PASS",
            "validated_at": utc_now(),
            "checks": [
                "SSH_HOST_KEY_MATCH",
                "EX4400_CHASSIS_IDENTITY_MATCH",
                "PLANNED_ENDPOINT_CONFIGURATION_PRESENT",
                "TARGET_DATA_VLAN_EXPLICITLY_ASSIGNED",
            ],
            "configuration": config_rows,
            "endpoint_evidence": endpoint_evidence,
            "warnings": [
                "%s has no expected MAC currently learned after commit"
                % row["new_interface"]
                for row in endpoint_evidence
                if not row["mac_evidence_present"]
            ],
        }
        transaction["commit"]["status"] = "VALIDATED_PENDING_FINAL_CONFIRMATION"
        persist_endpoint_transaction(migration_root, transaction, candidate_diff)

        if cu.commit(
            comment="Confirm EX migration %s endpoint activation %s"
            % (args.migration_id, transaction["transaction_id"]),
            timeout=120,
        ) is not True:
            raise base.ProvisioningError(
                "final EX4400 endpoint confirmation did not return success; confirmed rollback timer remains safety boundary"
            )
        commit_confirmed_started = False
        transaction["commit"]["status"] = "COMMITTED_AND_CONFIRMED"
        transaction["commit"]["confirmed"] = True
        transaction["commit"]["confirmed_at"] = utc_now()
        persist_endpoint_transaction(migration_root, transaction, candidate_diff)

        print("\nEX4400 endpoint activation transaction: PASS")
        print("  Transaction: %s" % transaction["transaction_id"])
        print("  Activated endpoint intents: %d" % len(correlation["activated"]))
        print("  Holds remaining: %d" % len(correlation["holds"]))
        print("  Commit-confirmed validation: PASS")
        print("  Final confirmation: PASS")
        print("  Record: %s" % (tx_dir / "transaction.json"))
        print("  QFX writes performed: no")
        print("  TEMP-RECOVERY cleanup performed: no")
        return 0

    except base.ProvisioningError as exc:
        if transaction is not None and commit_confirmed_started and cu is not None:
            transaction["validation"] = {
                "result": "FAIL",
                "validated_at": utc_now(),
                "error": str(exc),
                "checks": [],
                "endpoint_evidence": [],
            }
            try:
                cu.rollback(rb_id=1)
                if cu.commit(
                    comment="Rollback failed EX migration %s endpoint activation %s"
                    % (args.migration_id, transaction["transaction_id"]),
                    timeout=120,
                ) is not True:
                    raise base.ProvisioningError("explicit endpoint rollback commit did not return success")
                transaction["commit"]["status"] = "ROLLED_BACK_AFTER_VALIDATION_FAILURE"
                transaction["commit"]["rollback_at"] = utc_now()
                commit_confirmed_started = False
            except Exception as rollback_exc:
                transaction["commit"]["status"] = "AUTO_ROLLBACK_PENDING"
                transaction["commit"]["rollback_error"] = str(rollback_exc)
            persist_endpoint_transaction(migration_root, transaction, candidate_diff)
            raise base.ProvisioningError(
                "endpoint activation failed after commit confirmed; rollback status %s: %s"
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
        raise base.ProvisioningError("EX4400 endpoint activation failed: %s" % exc)
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
