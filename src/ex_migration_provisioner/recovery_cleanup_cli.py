from __future__ import annotations

import argparse
import sys
from pathlib import Path
from types import SimpleNamespace

from ex_migration_analyzer.core import read_json, sha256_bytes, sha256_file, utc_now

from . import cli_base as base
from .access_hardening import (
    classify_final_ports,
    current_port_states,
    edge_interfaces,
    final_production_vlan_names,
    hardening_statements,
    stale_vlan_cleanup,
    validate_final_hardening,
    validate_pre_hardening_config,
)
from .endpoint_stage import (
    committed_endpoint_state,
    qfx_plan_for_transaction,
    resolve_postcutover_access,
    validate_postcutover_access,
)
from .endpoint_stage_cli import (
    _bind_lab_identity_transport,
    _interfaces_config_set,
    _reconcile_completed_state,
    _validate_postcutover_identity,
)
from .inband import choose_qfx_transaction, planned_management_ip
from .prestage import choose_package_compat, validate_pre_cutover_site_policy
from .qfx_transaction import validate_post_commit_pair
from .recovery_cleanup import (
    build_cleanup_plan,
    build_cleanup_transaction,
    committed_cleanup_transactions,
    ex_recovery_state,
    inverse_statements,
    persist_cleanup_transaction,
    qfx_vlan_ids,
    validate_post_cleanup,
    validate_pre_cleanup,
    write_cleanup_plan,
)


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner cleanup",
        description=(
            "FINALIZATION: close the active TEMP-RECOVERY transit path while preserving a "
            "disabled local recovery attachment on the replacement EX, remove TEMP-RECOVERY "
            "from the migration QFX attachment, convert the EX uplink from 'all' to the "
            "current-plan QFX production VLAN set plus management, disable proven-unused "
            "non-recovery edge ports in the inactive default VLAN, and remove only "
            "proven-unused legacy data VLANs. State-only evidence never authorizes endpoint VLANs."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--environment", type=Path, default=Path("config/environment.lab.json"))
    parser.add_argument("--site-policy", type=Path)
    parser.add_argument("--identity-id")
    parser.add_argument("--package-id")
    parser.add_argument("--qfx-transaction-id")
    parser.add_argument(
        "--username",
        help="shared EX/QFX username; per-device username options override it",
    )
    parser.add_argument(
        "--password-env",
        help="environment variable containing the shared EX/QFX password; per-device options override it",
    )
    parser.add_argument("--ex-username")
    parser.add_argument("--ex-password-env")
    parser.add_argument("--qfx-username")
    parser.add_argument("--qfx-password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--confirm-minutes", type=int, default=10)
    parser.add_argument(
        "--plan-only",
        action="store_true",
        help="perform all read-only cleanup/hardening prechecks and create the immutable cleanup plan, but make no changes",
    )
    parser.add_argument(
        "--no-host-key-check",
        action="store_true",
        help="LAB ONLY: disable NETCONF known-host verification; pinned SSH fingerprints are still checked",
    )
    return parser


def _credentials(username, password_env, label):
    return base._credentials(
        SimpleNamespace(username=username, password_env=password_env),
        label,
    )


def _device_credentials(args):
    per_device_override = any((
        args.ex_username,
        args.ex_password_env,
        args.qfx_username,
        args.qfx_password_env,
    ))
    if not per_device_override:
        username, password = _credentials(args.username, args.password_env, "EX/QFX")
        return username, password, username, password

    ex_user, ex_password = _credentials(
        args.ex_username or args.username,
        args.ex_password_env or args.password_env,
        "EX4400",
    )
    qfx_user, qfx_password = _credentials(
        args.qfx_username or args.username,
        args.qfx_password_env or args.password_env,
        "QFX",
    )
    return ex_user, ex_password, qfx_user, qfx_password


def _normalize_diff(value):
    text = str(value or "")
    return text if not text or text.endswith("\n") else text + "\n"


def _full_config(dev):
    return dev.cli("show configuration | display set", warning=False) or ""


def _qfx_state(dev, plan_device, pair_validation):
    ae = plan_device["ae_interface"]
    ae_config = dev.cli(
        "show configuration interfaces %s | display set" % ae,
        warning=False,
    ) or ""
    vlan_config = (
        (dev.cli("show configuration vlans | display set", warning=False) or "")
        + "\n"
        + (dev.cli(
            'show configuration routing-instances | display set | match " vlan-id "',
            warning=False,
        ) or "")
    )
    value = qfx_vlan_ids(ae_config, vlan_config, ae)
    value.update({
        "ae_interface": ae,
        "physical_interface": plan_device["physical_interface"],
        "topology_result": pair_validation["result"],
    })
    return value


def _print_plan(value):
    hardening = value["access_hardening"]
    recovery_interface = value["recovery"]["interface"]
    used = [row["interface"] for row in hardening.get("used", [])]
    unused = [
        row["interface"] for row in hardening.get("unused", [])
        if row["interface"] != recovery_interface
    ]
    not_exposed = [row["interface"] for row in hardening.get("not_exposed", [])]
    stale = hardening.get("stale_vlans", {})
    print("\nMigration cleanup and access hardening plan")
    print("  Migration: %s" % value["migration_id"])
    print("  Cleanup plan: %s" % value["cleanup_plan_id"])
    print("  edge_ports definition: %s" % hardening.get("edge_ports_expression"))
    print("  Confirmed used edge ports kept enabled: %d" % len(used))
    if used:
        print("    %s" % ", ".join(used))
    print("  Configured unused non-recovery edge ports to disable: %d" % len(unused))
    if unused:
        print("    %s" % ", ".join(unused))
    if not_exposed:
        print("  Lab template-range ports not exposed by vJunos: %d" % len(not_exposed))
        print("    %s" % ", ".join(not_exposed))
    print(
        "  Recovery edge port: %s -> disable; preserve %s membership and VLAN definition"
        % (recovery_interface, value["recovery"]["vlan_name"])
    )
    print("  Inactive VLAN for disabled non-recovery ports: default (%s)" % value["recovery"]["prestage_default_vlan_id"])
    print("  EX uplink final VLANs: %s" % ", ".join(value["production_vlan_names"]))
    print("  EX voice policy: preserve broad edge_ports policy")
    if stale.get("delete"):
        print("  Proven-unused EX data VLANs to delete:")
        for item in stale["delete"]:
            print("    %s (%s)" % (item["name"], item["vlan_id"]))
    if stale.get("preserve"):
        print("  Non-required EX VLANs preserved by safety checks:")
        for item in stale["preserve"]:
            print("    %s (%s): %s" % (item["name"], item["vlan_id"], item["reason"]))
    print("  EX TEMP-RECOVERY: preserve local recovery-port membership and VLAN definition")
    for item in value["qfx_devices"]:
        print("  %s %s: remove %s from %s" % (
            item["role"],
            item["ae_interface"],
            value["recovery"]["vlan_name"],
            item["ae_interface"],
        ))
    print("  QFX global TEMP-RECOVERY VLAN definition: preserved")
    print("  Old EX VME/mgmt_junos configuration: untouched")
    print("  Result: %s" % value["result"])


def _print_failed_precheck(classification, config_precheck, precheck):
    print("\nCleanup precheck: FAIL")
    for row in classification.get("blockers", []):
        print("  Port BLOCK: %s | %s | %s" % (
            row["interface"], row["state"], row["reason"]
        ))
    for row in config_precheck.get("unexpected_unused_port_memberships", []):
        print("  Config BLOCK: %s unexpected VLAN membership(s): %s" % (
            row["interface"], ", ".join(row["unexpected"])
        ))
    for name, passed in sorted(config_precheck.get("checks", {}).items()):
        if not passed:
            print("  EX hardening FAIL: %s" % name)
    for name, passed in sorted(precheck.get("checks", {}).items()):
        if not passed:
            print("  Cleanup FAIL: %s" % name)
    print("  Device writes performed: no")


def _transaction_role(transaction, role):
    return transaction["devices"][role]


def _rollback_all(
    configs,
    role_statements,
    committed_roles,
    final_confirmed_roles,
    transaction,
    migration_root,
    candidate_diffs,
):
    errors = []
    for role in ("ex4400", "qfx-b", "qfx-a"):
        if role not in configs:
            continue
        cu = configs[role]
        try:
            if role in final_confirmed_roles:
                payload = "\n".join(inverse_statements(role_statements[role])) + "\n"
                cu.load(payload, format="set", merge=True)
                if cu.commit_check() is not True:
                    raise base.ProvisioningError("compensating rollback commit-check failed on %s" % role)
                if cu.commit(
                    comment="Compensating rollback EX migration %s cleanup %s"
                    % (transaction["migration_id"], transaction["transaction_id"]),
                    timeout=120,
                ) is not True:
                    raise base.ProvisioningError("compensating rollback commit failed on %s" % role)
                _transaction_role(transaction, role)["commit_status"] = "COMPENSATING_ROLLBACK_COMMITTED"
            elif role in committed_roles:
                cu.rollback(rb_id=1)
                if cu.commit(
                    comment="Rollback EX migration %s cleanup %s"
                    % (transaction["migration_id"], transaction["transaction_id"]),
                    timeout=120,
                ) is not True:
                    raise base.ProvisioningError("rollback commit failed on %s" % role)
                _transaction_role(transaction, role)["commit_status"] = "ROLLED_BACK"
            else:
                cu.rollback()
                _transaction_role(transaction, role)["commit_status"] = "CANDIDATE_ROLLED_BACK"
        except Exception as exc:
            errors.append("%s: %s" % (role, exc))
            _transaction_role(transaction, role)["commit_status"] = "ROLLBACK_FAILED"
    transaction["status"] = "ROLLED_BACK" if not errors else "ROLLBACK_INCOMPLETE"
    transaction["rollback_at"] = utc_now()
    if errors:
        transaction["rollback_errors"] = errors
    persist_cleanup_transaction(migration_root, transaction, candidate_diffs)
    return errors


def run(argv):
    args = _parser().parse_args(argv)
    if args.confirm_minutes < 1:
        raise base.ProvisioningError("--confirm-minutes must be at least 1")

    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected_plan = base.choose_approved_plan(migration_root)

    completed_cleanup = committed_cleanup_transactions(
        migration_root,
        selected_plan["plan_digest"],
    )
    if completed_cleanup:
        tx = completed_cleanup[0]["transaction"]
        print("Cleanup is already committed and confirmed for the current approved migration plan.")
        print("  Transaction: %s" % tx["transaction_id"])
        print("  Device writes performed: no")
        return 0

    selected_identity = base.choose_identity(migration_root, args.identity_id)
    selected_package = choose_package_compat(migration_root, args.package_id)
    package = selected_package["package"]
    if package.get("inputs", {}).get("plan_digest") != selected_plan["plan_digest"]:
        raise base.ProvisioningError(
            "selected pre-stage package is bound to a different approved migration plan"
        )

    qfx_selected = choose_qfx_transaction(
        migration_root,
        args.qfx_transaction_id,
        approved_plan_digest=selected_plan["plan_digest"],
    )
    qfx_transaction = qfx_selected["transaction"]
    selected_qfx_plan = qfx_plan_for_transaction(
        migration_root,
        qfx_transaction,
        selected_plan["plan_digest"],
    )
    qfx_plan = selected_qfx_plan["plan"]

    paths = base._provisioning_paths(settings)
    if args.site_policy:
        paths["site_policy"] = args.site_policy
    if not paths["site_policy"].is_file():
        raise base.ProvisioningError("QFX site policy is missing: %s" % paths["site_policy"])
    policy = validate_pre_cutover_site_policy(read_json(paths["site_policy"]))
    policy_digest = sha256_file(paths["site_policy"])
    if package.get("inputs", {}).get("site_policy_digest") != policy_digest:
        raise base.ProvisioningError("selected package is stale: QFX site policy changed")
    if qfx_plan.get("inputs", {}).get("site_policy_digest") != policy_digest:
        raise base.ProvisioningError("selected QFX transaction is stale: QFX site policy changed")
    if args.no_host_key_check and policy["environment"] != "lab":
        raise base.ProvisioningError("--no-host-key-check is permitted only by a lab site policy")
    if not args.plan_only and policy["environment"] != "lab":
        raise base.ProvisioningError(
            "live cleanup writes are restricted to LAB_ONLY until the cleanup transaction is validated end-to-end"
        )

    profile = read_json(args.environment)
    profile = _bind_lab_identity_transport(profile, selected_identity["identity"])
    profile = validate_postcutover_access(profile)
    management_ip = planned_management_ip(selected_plan["plan"])
    access = resolve_postcutover_access(profile, management_ip)
    allow_unobserved_template_ports = (
        policy["environment"] == "lab" and bool(access.get("allow_vjunos_switch"))
    )

    variables = package.get("variables", {})
    recovery_interface = str(variables.get("recovery_interface") or "")
    recovery_vlan_name = str(variables.get("temporary_recovery_vlan_name") or "")
    recovery_vlan_id = int(variables.get("temporary_recovery_vlan_id"))
    prestage_vlan_id = int(variables.get("prestage_access_vlan_id"))
    management_vlan_id = int(variables.get("management_vlan_id"))
    voice_vlan_name = str(variables.get("voice_vlan") or "")
    uplink_interfaces = list(variables.get("uplink_interfaces") or [])
    configured_vlans = list(variables.get("configured_vlans") or [])
    if not recovery_interface or not recovery_vlan_name or not voice_vlan_name or not uplink_interfaces:
        raise base.ProvisioningError("selected package is missing cleanup/hardening variables")
    if recovery_vlan_name != policy["temporary_recovery_vlan"]["name"] or recovery_vlan_id != int(policy["temporary_recovery_vlan"]["vlan_id"]):
        raise base.ProvisioningError("package recovery VLAN does not match QFX site policy")

    required_qfx_vlan_ids = list(qfx_plan.get("derivation", {}).get("required_vlan_ids") or [])
    production_vlan_names = final_production_vlan_names(
        configured_vlans,
        management_vlan_id,
        required_qfx_vlan_ids,
    )
    final_vlan_ids = sorted(set(int(value) for value in required_qfx_vlan_ids) | {management_vlan_id})
    historical_completed = committed_endpoint_state(
        migration_root,
        selected_plan["plan_digest"],
    )

    ex_user, ex_password, qfx_user, qfx_password = _device_credentials(args)

    from jnpr.junos import Device
    from jnpr.junos.utils.config import Config

    ex_dev = None
    qfx_devices = {}
    opened = []
    configs = {}
    locked_roles = []
    candidate_diffs = {}
    committed_roles = []
    final_confirmed_roles = []
    transaction = None
    role_statements = {}

    try:
        transport = access["transport_address"]
        port = access["port"]
        bound_fingerprint = (
            selected_identity["identity"]
            .get("observed", {})
            .get("connection", {})
            .get("ssh_host_key_sha256")
        )
        ex_fingerprint = base.ssh_host_key_fingerprint(transport, port)
        if ex_fingerprint != bound_fingerprint:
            raise base.ProvisioningError("EX4400 SSH host key does not match approved identity")
        print("Connecting to EX4400 at %s:%s..." % (transport, port))
        ex_dev = Device(host=transport, user=ex_user, passwd=ex_password, port=port, gather_facts=True)
        ex_dev.open(auto_probe=10, hostkey_verify=False)
        opened.append(ex_dev)
        current_identity = base.observe_ex4400_identity(
            ex_dev,
            management_ip,
            port,
            ex_fingerprint,
            allow_vjunos_switch=access["allow_vjunos_switch"],
        )
        expected_ex_hostname = str(selected_plan["plan"].get("template_variables", {}).get("new_hostname") or "")
        _validate_postcutover_identity(current_identity, selected_identity["identity"], expected_ex_hostname)

        qfx_plan_by_role = {item["role"]: item for item in qfx_plan["devices"]}
        for device_policy in policy["qfx_pair"]:
            role = device_policy["role"]
            plan_device = qfx_plan_by_role[role]
            address = device_policy["management_address"]
            print("Connecting to %s at %s..." % (device_policy["expected_hostname"], address))
            fingerprint = base.ssh_host_key_fingerprint(address, args.port)
            if fingerprint != plan_device.get("ssh_host_key_sha256"):
                raise base.ProvisioningError("%s SSH host key changed since approved QFX staging" % role)
            dev = Device(host=address, user=qfx_user, passwd=qfx_password, port=args.port, gather_facts=True)
            dev.open(auto_probe=10, hostkey_verify=not args.no_host_key_check)
            facts = getattr(dev, "facts", {}) or {}
            if str(facts.get("hostname") or "").lower() != str(device_policy["expected_hostname"]).lower():
                raise base.ProvisioningError("%s hostname does not match QFX site policy" % role)
            if str(facts.get("model") or "").lower() != str(device_policy["expected_model"]).lower():
                raise base.ProvisioningError("%s model does not match QFX site policy" % role)
            qfx_devices[role] = dev
            opened.append(dev)

        ex_interfaces = _interfaces_config_set(ex_dev, "committed")
        live_completed = _reconcile_completed_state(ex_interfaces, historical_completed)
        ex_config = _full_config(ex_dev)
        terse_text = ex_dev.cli("show interfaces terse", warning=False) or ""
        mac_text = ex_dev.cli("show ethernet-switching table extensive", warning=False) or ""
        member_ids = [
            int(item["member_id"])
            for item in selected_identity["identity"].get("observed", {}).get("device", {}).get("members", [])
        ]
        if not member_ids:
            raise base.ProvisioningError("approved identity has no VC member inventory")
        eligible_edges = edge_interfaces(ex_config, member_ids, uplink_interfaces)
        if recovery_interface not in eligible_edges:
            raise base.ProvisioningError("approved recovery interface is outside the live template-owned edge_ports range")
        port_states = current_port_states(terse_text, mac_text, eligible_edges, observed_at=utc_now())
        classification = classify_final_ports(
            selected_plan["plan"],
            live_completed["by_old"],
            port_states,
            recovery_interface,
            allow_unobserved_template_ports=allow_unobserved_template_ports,
        )
        classification["lab_unobserved_template_ports_allowed"] = allow_unobserved_template_ports
        config_precheck = validate_pre_hardening_config(
            ex_config,
            classification,
            recovery_interface,
            recovery_vlan_name,
            voice_vlan_name,
        )
        classification["configuration_precheck"] = config_precheck
        classification["edge_ports_expression"] = config_precheck.get("edge_ports_expression")
        if config_precheck["result"] != "PASS":
            classification["result"] = "FAIL"

        stale_vlans = stale_vlan_cleanup(
            ex_config,
            mac_text,
            configured_vlans,
            final_vlan_ids,
            observed_at=utc_now(),
        )
        classification["stale_vlans"] = stale_vlans
        classification["final_uplink_vlan_names"] = production_vlan_names

        ex_state = ex_recovery_state(
            ex_config,
            recovery_interface,
            recovery_vlan_name,
            recovery_vlan_id,
            prestage_vlan_id,
        )
        pair_validation = validate_post_commit_pair(
            qfx_devices,
            qfx_plan,
            expected_ex_hostname,
        )
        qfx_states = {
            role: _qfx_state(qfx_devices[role], qfx_plan_by_role[role], pair_validation)
            for role in sorted(qfx_devices)
        }
        precheck = validate_pre_cleanup(
            selected_plan["plan"],
            live_completed["by_old"],
            ex_state,
            qfx_states,
            management_vlan_id,
            recovery_vlan_id,
            recovery_vlan_name,
            required_qfx_vlan_ids,
            classification,
        )
        if precheck["result"] != "PASS":
            _print_failed_precheck(classification, config_precheck, precheck)
            return 2

        used_interfaces = [row["interface"] for row in classification["used"]]
        unused_interfaces = [
            row["interface"] for row in classification["unused"]
            if row["interface"] != recovery_interface
        ]
        not_exposed_interfaces = [row["interface"] for row in classification["not_exposed"]]
        deleted_vlan_names = [row["name"] for row in stale_vlans["delete"]]
        hardening = hardening_statements(
            ex_config,
            unused_interfaces,
            used_interfaces,
            production_vlan_names,
            voice_vlan_name,
            recovery_vlan_name,
            stale_vlan_names=deleted_vlan_names,
        )
        qfx_ae_by_role = {
            role: qfx_plan_by_role[role]["ae_interface"]
            for role in sorted(qfx_plan_by_role)
        }
        cleanup_plan = build_cleanup_plan(
            args.migration_id,
            selected_plan["plan"],
            selected_plan["plan_digest"],
            package["package_id"],
            sha256_file(selected_package["package_path"]),
            selected_identity["identity"]["identity_id"],
            sha256_file(selected_identity["identity_path"]),
            qfx_transaction["transaction_id"],
            sha256_file(qfx_selected["transaction_path"]),
            qfx_plan["qfx_plan_id"],
            policy["site_policy_id"],
            policy_digest,
            recovery_interface,
            recovery_vlan_name,
            recovery_vlan_id,
            prestage_vlan_id,
            ex_state.get("recovery_port_disabled", False),
            qfx_ae_by_role,
            precheck,
            classification,
            hardening,
            production_vlan_names,
            created_at=utc_now(),
        )
        cleanup_dir, cleanup_plan, action = write_cleanup_plan(migration_root, cleanup_plan)
        _print_plan(cleanup_plan)
        print("  Plan artifact: %s (%s)" % (cleanup_dir / "plan.json", action))
        if args.plan_only:
            print("  Device writes performed: no (--plan-only)")
            return 0

        role_statements["ex4400"] = cleanup_plan["ex4400"]["statements"]
        for item in cleanup_plan["qfx_devices"]:
            role_statements[item["role"]] = item["statements"]

        for role, dev in (("qfx-a", qfx_devices["qfx-a"]), ("qfx-b", qfx_devices["qfx-b"]), ("ex4400", ex_dev)):
            cu = Config(dev)
            cu.lock()
            configs[role] = cu
            locked_roles.append(role)
            if cu.diff():
                raise base.ProvisioningError("%s candidate already contains uncommitted changes" % role)

        locked_pair = validate_post_commit_pair(qfx_devices, qfx_plan, expected_ex_hostname)
        if locked_pair["result"] != "PASS":
            raise base.ProvisioningError("QFX topology changed after cleanup locks were acquired")
        locked_interfaces = _interfaces_config_set(ex_dev, "committed")
        locked_completed = _reconcile_completed_state(locked_interfaces, historical_completed)
        if set(locked_completed["by_old"]) != set(live_completed["by_old"]):
            raise base.ProvisioningError("EX endpoint completion state changed after cleanup locks were acquired")

        locked_terse = ex_dev.cli("show interfaces terse", warning=False) or ""
        locked_mac = ex_dev.cli("show ethernet-switching table extensive", warning=False) or ""
        locked_states = current_port_states(
            locked_terse,
            locked_mac,
            eligible_edges,
            observed_at=utc_now(),
        )
        locked_classification = classify_final_ports(
            selected_plan["plan"],
            locked_completed["by_old"],
            locked_states,
            recovery_interface,
            allow_unobserved_template_ports=allow_unobserved_template_ports,
        )
        if locked_classification["result"] != "PASS":
            raise base.ProvisioningError("EX access-port safety state changed after cleanup locks were acquired")
        locked_used = {row["interface"] for row in locked_classification["used"]}
        locked_unused = {
            row["interface"] for row in locked_classification["unused"]
            if row["interface"] != recovery_interface
        }
        locked_not_exposed = {row["interface"] for row in locked_classification["not_exposed"]}
        if locked_used != set(used_interfaces) or locked_unused != set(unused_interfaces) or locked_not_exposed != set(not_exposed_interfaces):
            raise base.ProvisioningError("EX access-port classification changed after cleanup locks were acquired")

        locked_stale_vlans = stale_vlan_cleanup(
            ex_config,
            locked_mac,
            configured_vlans,
            final_vlan_ids,
            observed_at=utc_now(),
        )
        if {row["name"] for row in locked_stale_vlans["delete"]} != set(deleted_vlan_names):
            raise base.ProvisioningError("EX stale-VLAN safety evidence changed after cleanup locks were acquired")

        for role in ("qfx-a", "qfx-b", "ex4400"):
            payload = "\n".join(role_statements[role]) + "\n"
            configs[role].load(payload, format="set", merge=True)
            if configs[role].commit_check() is not True:
                raise base.ProvisioningError("%s cleanup commit-check did not return PASS" % role)
            candidate_diffs[role] = _normalize_diff(configs[role].diff())
            if not candidate_diffs[role]:
                raise base.ProvisioningError("%s cleanup produced no candidate diff" % role)

        if candidate_diffs["qfx-a"] != candidate_diffs["qfx-b"]:
            raise base.ProvisioningError("QFX cleanup candidate diffs are not symmetric")

        print("\nCleanup candidate diffs")
        for role in ("ex4400", "qfx-a", "qfx-b"):
            print("\n  %s SHA256: %s" % (role, sha256_bytes(candidate_diffs[role].encode("utf-8"))))
            print(candidate_diffs[role].rstrip())
        print("\n  Commit check: PASS on EX4400 and both QFXs")
        answer = input(
            "\nApprove exactly these diffs, CLOSE the upstream TEMP-RECOVERY path, preserve the disabled local EX4400 recovery attachment, prune the listed proven-unused VLANs, and disable the listed unused EX4400 ports? [y/N]: "
        ).strip().lower()
        if answer not in ("y", "yes"):
            for role in reversed(locked_roles):
                configs[role].rollback()
            print("Cleanup was not approved; no commit was performed.")
            return 1

        transaction = build_cleanup_transaction(
            cleanup_plan,
            candidate_diffs,
            approved_at=utc_now(),
            confirm_minutes=args.confirm_minutes,
        )
        tx_dir = persist_cleanup_transaction(migration_root, transaction, candidate_diffs)

        for role in ("qfx-a", "qfx-b", "ex4400"):
            if configs[role].commit(
                confirm=args.confirm_minutes,
                comment="EX migration %s final cleanup %s" % (args.migration_id, transaction["transaction_id"]),
                timeout=120,
            ) is not True:
                raise base.ProvisioningError("%s cleanup commit confirmed did not return success" % role)
            committed_roles.append(role)
            _transaction_role(transaction, role)["commit_status"] = "CONFIRMED_PENDING_VALIDATION"
            transaction["status"] = "COMMIT_CONFIRMED_PENDING_VALIDATION"
            persist_cleanup_transaction(migration_root, transaction, candidate_diffs)

        post_ex_fingerprint = base.ssh_host_key_fingerprint(transport, port)
        if post_ex_fingerprint != bound_fingerprint:
            raise base.ProvisioningError("EX4400 SSH host key changed after cleanup commit confirmed")
        post_identity = base.observe_ex4400_identity(
            ex_dev,
            management_ip,
            port,
            post_ex_fingerprint,
            allow_vjunos_switch=access["allow_vjunos_switch"],
        )
        _validate_postcutover_identity(post_identity, selected_identity["identity"], expected_ex_hostname)

        post_interfaces = _interfaces_config_set(ex_dev, "committed")
        post_completed = _reconcile_completed_state(post_interfaces, historical_completed)
        post_ex_config = _full_config(ex_dev)
        post_terse = ex_dev.cli("show interfaces terse", warning=False) or ""
        post_mac = ex_dev.cli("show ethernet-switching table extensive", warning=False) or ""
        post_states = current_port_states(post_terse, post_mac, eligible_edges, observed_at=utc_now())
        hardening_validation = validate_final_hardening(
            post_ex_config,
            post_states,
            used_interfaces,
            unused_interfaces,
            production_vlan_names,
            voice_vlan_name,
            deleted_vlan_names=deleted_vlan_names,
            expected_edge_expression=classification["edge_ports_expression"],
        )
        post_ex_state = ex_recovery_state(
            post_ex_config,
            recovery_interface,
            recovery_vlan_name,
            recovery_vlan_id,
            prestage_vlan_id,
        )

        for role, plan_device in sorted(qfx_plan_by_role.items()):
            current_key = base.ssh_host_key_fingerprint(plan_device["management_address"], args.port)
            if current_key != plan_device.get("ssh_host_key_sha256"):
                raise base.ProvisioningError("%s SSH host key changed after cleanup commit confirmed" % role)
        post_pair = validate_post_commit_pair(qfx_devices, qfx_plan, expected_ex_hostname)
        post_qfx_states = {
            role: _qfx_state(qfx_devices[role], qfx_plan_by_role[role], post_pair)
            for role in sorted(qfx_devices)
        }
        validation = validate_post_cleanup(
            selected_plan["plan"],
            post_completed["by_old"],
            post_ex_state,
            post_qfx_states,
            management_vlan_id,
            recovery_vlan_id,
            recovery_vlan_name,
            required_qfx_vlan_ids,
            hardening_validation,
        )
        transaction["validation"] = validation
        if validation["result"] != "PASS":
            raise base.ProvisioningError("post-cleanup validation failed")
        transaction["status"] = "VALIDATED_PENDING_FINAL_CONFIRMATION"
        persist_cleanup_transaction(migration_root, transaction, candidate_diffs)

        for role in ("qfx-a", "qfx-b", "ex4400"):
            if configs[role].commit(
                comment="Confirm EX migration %s final cleanup %s" % (args.migration_id, transaction["transaction_id"]),
                timeout=120,
            ) is not True:
                raise base.ProvisioningError("%s final cleanup confirmation failed" % role)
            final_confirmed_roles.append(role)
            _transaction_role(transaction, role)["commit_status"] = "COMMITTED_AND_CONFIRMED"
            persist_cleanup_transaction(migration_root, transaction, candidate_diffs)

        transaction["status"] = "COMMITTED_AND_CONFIRMED"
        transaction["confirmed_at"] = utc_now()
        persist_cleanup_transaction(migration_root, transaction, candidate_diffs)

        print("\nMigration cleanup transaction: PASS")
        print("  Transaction: %s" % transaction["transaction_id"])
        print("  Used EX4400 edge ports kept enabled: %d" % len(used_interfaces))
        print("  Unused non-recovery EX4400 edge ports disabled: %d" % len(unused_interfaces))
        if not_exposed_interfaces:
            print("  Lab template-range ports not exposed by vJunos: %d" % len(not_exposed_interfaces))
        print("  Recovery EX4400 edge port disabled with TEMP-RECOVERY preserved: PASS")
        print("  Broad edge_ports voice policy preserved: PASS")
        print("  Final ae0 VLAN membership exact: PASS")
        print("  Proven-unused EX data VLANs removed: %d" % len(deleted_vlan_names))
        print("  Inactive VLAN 3998 excluded from ae0: PASS")
        print("  TEMP-RECOVERY removed from production EX uplink: PASS")
        print("  TEMP-RECOVERY removed from migration QFX AE pair: PASS")
        print("  QFX global TEMP-RECOVERY definition preserved: PASS")
        print("  Commit-confirmed validation: PASS")
        print("  Final confirmation: PASS")
        print("  Record: %s" % (tx_dir / "transaction.json"))
        print("  Old EX VME/mgmt_junos writes performed: no")
        return 0

    except base.ProvisioningError as exc:
        if transaction is not None:
            transaction["validation"] = {
                "result": "FAIL",
                "validated_at": utc_now(),
                "error": str(exc),
                "checks": {},
            }
            rollback_errors = _rollback_all(
                configs,
                role_statements,
                committed_roles,
                final_confirmed_roles,
                transaction,
                migration_root,
                candidate_diffs,
            )
            if rollback_errors:
                raise base.ProvisioningError(
                    "%s; cleanup rollback incomplete: %s" % (exc, "; ".join(rollback_errors))
                )
        raise
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
    except (base.AnalysisError, base.ProvisioningError, base.WriteError, OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())