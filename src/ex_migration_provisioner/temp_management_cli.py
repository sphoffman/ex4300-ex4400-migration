from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from ex_migration_analyzer.core import atomic_json, canonical_bytes, read_json, sha256_bytes, sha256_file, utc_now

from . import cli_base as base


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner stage-old-recovery",
        description=(
            "PRE-CUTOVER: stage the old EX4300 temporary-management transit used by the "
            "replacement EX4400 fxp0. This configures one proven-unused old-EX access port "
            "in the site Temp-Management VLAN and preserves the old switch's existing "
            "management identity."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--transport-address", help="LAB ONLY: reachable old-switch transport override")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--confirm-minutes", type=int, default=10)
    parser.add_argument("--no-host-key-check", action="store_true")
    return parser


def _site_policy(settings):
    path = Path(settings.get("qfx_site_policy", "config/qfx-site-policy.active.json"))
    if not path.is_file():
        raise base.ProvisioningError("QFX site policy is missing: %s" % path)
    policy = read_json(path)
    environment = str(policy.get("environment") or "")
    if environment not in ("lab", "production"):
        raise base.ProvisioningError("QFX site policy environment must be lab or production")
    vlan = policy.get("temporary_recovery_vlan") or {}
    name = str(vlan.get("name") or "").strip()
    vlan_id = vlan.get("vlan_id")
    if not name or not isinstance(vlan_id, int) or not 1 <= vlan_id <= 4094:
        raise base.ProvisioningError("site policy has no valid Temp-Management VLAN")
    return policy, path, {"name": name, "vlan_id": vlan_id}


def _select_temp_management_port(plan):
    candidates = []
    for item in plan.get("port_intents", []):
        if item.get("planned_action") != "LEAVE_TEMPLATE_DEFAULT":
            continue
        name = str(item.get("old_interface") or "")
        match = re.fullmatch(r"ge-(\d+)/(\d+)/(\d+)", name)
        if not match:
            continue
        member, pic, port = (int(value) for value in match.groups())
        candidates.append(((member, pic, port), name, item))
    if not candidates:
        raise base.ProvisioningError(
            "no proven-unused old EX4300 access port is available for temporary management"
        )
    candidates.sort(reverse=True, key=lambda value: value[0])
    _key, name, item = candidates[0]
    return name, item


def _config_lines(text):
    return {line.strip() for line in str(text or "").splitlines() if line.strip()}


def _candidate_statements(config_text, port, vlan):
    lines = _config_lines(config_text)
    vlan_name = vlan["name"]
    vlan_id = vlan["vlan_id"]

    expected_vlan = "set vlans %s vlan-id %s" % (vlan_name, vlan_id)
    conflicting_vlan_ids = sorted(
        line for line in lines
        if line.startswith("set vlans %s vlan-id " % vlan_name) and line != expected_vlan
    )
    if conflicting_vlan_ids:
        raise base.ProvisioningError(
            "existing Temp-Management VLAN name has a conflicting VLAN ID: %s"
            % "; ".join(conflicting_vlan_ids)
        )

    port_prefix = "set interfaces %s " % port
    existing_port = sorted(line for line in lines if line.startswith(port_prefix))
    if existing_port:
        raise base.ProvisioningError(
            "selected temporary-management port %s is not configuration-empty: %s"
            % (port, "; ".join(existing_port))
        )

    ae0_prefix = "set interfaces ae0 unit 0 family ethernet-switching "
    ae0_lines = sorted(line for line in lines if line.startswith(ae0_prefix))
    if not ae0_lines:
        raise base.ProvisioningError(
            "old EX4300 ae0 ethernet-switching trunk was not found; cannot prove Temp-Management upstream transit"
        )
    if not any(line == ae0_prefix + "interface-mode trunk" for line in ae0_lines):
        raise base.ProvisioningError("old EX4300 ae0 is not an ethernet-switching trunk")

    statements = []
    if expected_vlan not in lines:
        statements.append(expected_vlan)
    statements.extend([
        "set interfaces %s unit 0 family ethernet-switching interface-mode access" % port,
        "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (port, vlan_name),
    ])

    members_all = ae0_prefix + "vlan members all"
    explicit_member = ae0_prefix + "vlan members %s" % vlan_name
    if members_all not in lines and explicit_member not in lines:
        statements.append(explicit_member)
    return statements


def _validate_committed(dev, port, vlan):
    text = dev.cli("show configuration interfaces | display set", warning=False) or ""
    vlan_text = dev.cli("show configuration vlans | display set", warning=False) or ""
    lines = _config_lines(text + "\n" + vlan_text)
    required = {
        "set vlans %s vlan-id %s" % (vlan["name"], vlan["vlan_id"]),
        "set interfaces %s unit 0 family ethernet-switching interface-mode access" % port,
        "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (port, vlan["name"]),
    }
    missing = sorted(required - lines)
    if missing:
        raise base.ProvisioningError(
            "old EX4300 temporary-management validation is incomplete: %s" % "; ".join(missing)
        )
    ae_all = "set interfaces ae0 unit 0 family ethernet-switching vlan members all"
    ae_named = "set interfaces ae0 unit 0 family ethernet-switching vlan members %s" % vlan["name"]
    if ae_all not in lines and ae_named not in lines:
        raise base.ProvisioningError("old EX4300 ae0 does not carry Temp-Management after commit")


def _persist(root, value, diff):
    destination = root / "old-switch" / "recovery-transactions" / value["transaction_id"]
    destination.mkdir(parents=True, exist_ok=True)
    tx_path = destination / "transaction.json"
    diff_path = destination / "candidate.diff"
    normalized = str(diff or "")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    diff_path.write_text(normalized, encoding="utf-8")
    atomic_json(tx_path, value)
    atomic_json(destination / "integrity.json", {
        "transaction.json": sha256_file(tx_path),
        "candidate.diff": sha256_file(diff_path),
    })
    return destination


def main(argv=None):
    args = _parser().parse_args(argv)
    if not 1 <= args.confirm_minutes <= 60:
        raise base.ProvisioningError("--confirm-minutes must be between 1 and 60")

    settings = base.load_settings(args.settings)
    policy, policy_path, vlan = _site_policy(settings)
    environment = policy["environment"]
    if environment != "lab" and (args.transport_address or args.no_host_key_check):
        raise base.ProvisioningError(
            "transport override and --no-host-key-check are permitted only by a lab site policy"
        )

    root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected = base.choose_approved_plan(root)
    plan = selected["plan"]
    expected_hostname = str(plan.get("template_variables", {}).get("old_hostname") or "").strip()
    management_ip = str(plan.get("template_variables", {}).get("management_ip") or "").strip()
    if not expected_hostname or not management_ip:
        raise base.ProvisioningError("approved plan is missing old hostname or management IP")

    temp_port, port_intent = _select_temp_management_port(plan)
    source_transport = str(args.transport_address or management_ip)
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
    try:
        print("\nOld EX4300 temporary-management pre-stage")
        print("  Source switch: %s" % expected_hostname)
        print("  Temp-Management VLAN: %s (%s)" % (vlan["name"], vlan["vlan_id"]))
        print("  Reserved old-EX access port: %s" % temp_port)
        print("  Purpose: connect replacement EX4400 fxp0 before physical cutover")
        print("  Old EX management identity: preserved")
        print("Connecting to old EX4300 at %s:%s..." % (source_transport, args.port))
        dev.open(auto_probe=10, hostkey_verify=not args.no_host_key_check)
        observed_hostname = str((getattr(dev, "facts", {}) or {}).get("hostname") or "").strip()
        if observed_hostname.lower() != expected_hostname.lower():
            raise base.ProvisioningError(
                "old-switch hostname %r does not match approved source hostname %r"
                % (observed_hostname, expected_hostname)
            )

        config = dev.cli("show configuration interfaces | display set", warning=False) or ""
        vlan_config = dev.cli("show configuration vlans | display set", warning=False) or ""
        statements = _candidate_statements(config + "\n" + vlan_config, temp_port, vlan)
        payload = "\n".join(statements) + "\n"

        cu = Config(dev)
        cu.lock()
        locked = True
        if cu.diff():
            raise base.ProvisioningError("old EX4300 candidate already contains uncommitted changes")
        cu.load(payload, format="set", merge=True)
        if cu.commit_check() is not True:
            raise base.ProvisioningError("old EX4300 Temp-Management commit-check did not return PASS")
        candidate_diff = str(cu.diff() or "")

        key = {
            "migration_id": args.migration_id,
            "plan_digest": selected["plan_digest"],
            "site_policy_digest": sha256_file(policy_path),
            "temporary_management_vlan": vlan,
            "temporary_management_port": temp_port,
            "candidate_diff_sha256": sha256_bytes(candidate_diff.encode("utf-8")),
        }
        transaction = {
            "schema_version": "2.0",
            "transaction_id": sha256_bytes(canonical_bytes(key))[:16],
            "migration_id": args.migration_id,
            "phase": "pre_cutover_temporary_management",
            "created_at": utc_now(),
            "inputs": {
                "plan_id": plan.get("plan_id"),
                "plan_digest": selected["plan_digest"],
                "plan_approval_digest": selected["approval_digest"],
                "site_policy_digest": sha256_file(policy_path),
            },
            "source": {
                "hostname": expected_hostname,
                "transport_address": source_transport,
                "ssh_host_key_sha256": source_fingerprint,
            },
            "temporary_management": {
                "vlan": vlan,
                "old_ex_access_port": temp_port,
                "port_evidence": port_intent,
                "replacement_connection": "EX4400 fxp0",
                "upstream_interface": "ae0",
            },
            "commit": {
                "status": "APPROVED_PENDING_COMMIT",
                "confirmed": False,
                "confirm_minutes": args.confirm_minutes,
            },
            "validation": {"result": "PENDING", "checks": []},
            "safety": {
                "old_ex_management_identity_changed": False,
                "old_ex_vme_changed": False,
                "proven_unused_access_port_required": True,
                "commit_confirmed_required": True,
            },
        }

        if not candidate_diff:
            _validate_committed(dev, temp_port, vlan)
            transaction["commit"] = {
                "status": "ALREADY_PRESENT_VALIDATED",
                "confirmed": True,
                "confirmed_at": utc_now(),
                "confirm_minutes": args.confirm_minutes,
            }
            transaction["validation"] = {
                "result": "PASS",
                "validated_at": utc_now(),
                "checks": ["TEMP_MANAGEMENT_VLAN_PRESENT", "RESERVED_ACCESS_PORT_PRESENT", "AE0_TRANSIT_PRESENT"],
            }
            directory = _persist(root, transaction, "")
            print("Old EX4300 temporary-management pre-stage: PASS (already present)")
            print("  Record: %s" % (directory / "transaction.json"))
            return 0

        print("\nOld EX4300 Temp-Management candidate diff")
        print(candidate_diff.rstrip())
        answer = input("\nApprove exactly this temporary-management candidate for commit confirmed? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            cu.rollback()
            print("Temporary-management candidate was not approved; no commit was performed.")
            return 1

        directory = _persist(root, transaction, candidate_diff)
        cu.commit(confirm=args.confirm_minutes, comment="EX migration %s temporary management" % args.migration_id)
        commit_confirmed_started = True
        _validate_committed(dev, temp_port, vlan)
        transaction["validation"] = {
            "result": "PASS",
            "validated_at": utc_now(),
            "checks": ["TEMP_MANAGEMENT_VLAN_PRESENT", "RESERVED_ACCESS_PORT_PRESENT", "AE0_TRANSIT_PRESENT"],
        }
        cu.commit(comment="EX migration %s temporary management confirmed" % args.migration_id)
        commit_confirmed_started = False
        transaction["commit"] = {
            "status": "COMMITTED_AND_CONFIRMED",
            "confirmed": True,
            "confirmed_at": utc_now(),
            "confirm_minutes": args.confirm_minutes,
        }
        _persist(root, transaction, candidate_diff)
        print("\nOld EX4300 temporary-management pre-stage: PASS")
        print("  Reserved access port: %s" % temp_port)
        print("  Connect replacement EX4400 fxp0 to this port before cutover.")
        print("  Record: %s" % (directory / "transaction.json"))
        return 0
    except Exception:
        if cu is not None and locked and not commit_confirmed_started:
            try:
                cu.rollback()
            except Exception:
                pass
        raise
    finally:
        if cu is not None and locked:
            try:
                cu.unlock()
            except Exception:
                pass
        try:
            dev.close()
        except Exception:
            pass


def run(argv=None):
    return main(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (base.AnalysisError, base.ProvisioningError, base.WriteError, OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        raise SystemExit(2)
