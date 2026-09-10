from __future__ import annotations

import argparse
import getpass
import os
import sys

from ex_migration_analyzer.core import utc_now
from ex_migration_provisioner import cli_base as provisioner_base

from .core import (
    SiteError,
    active_policy_path,
    build_active_policy,
    build_profile,
    build_site_discovery,
    build_site_inventory,
    load_profile,
    load_settings,
    observe_qfx,
    profile_path,
    site_discovery_candidates,
    site_inventory_candidates,
    stage_statements,
    validate_staged_device,
    write_active_policy,
    write_profile,
    write_site_discovery,
    write_site_inventory,
)


def _prompt(value, label, default=None):
    if value is not None:
        return str(value).strip()
    suffix = " [%s]" % default if default is not None else ""
    answer = input("%s%s: " % (label, suffix)).strip()
    return answer or (str(default) if default is not None else "")


def _prompt_int(value, label, default):
    try:
        return int(_prompt(value, label, default))
    except ValueError:
        raise SiteError("%s must be an integer" % label)


def _credentials(args, label="QFX site"):
    username = args.username or input("%s username: " % label).strip()
    if not username:
        raise SiteError("username must not be empty")
    if args.password_env:
        password = os.environ.get(args.password_env)
        if password is None:
            raise SiteError("environment variable %s is not set" % args.password_env)
    else:
        password = getpass.getpass("%s password: " % label)
    return username, password


def _connect_pair(profile, username, password, port, no_host_key_check=False):
    if no_host_key_check and profile["environment"] != "lab":
        raise SiteError("--no-host-key-check is permitted only for a lab site")
    from jnpr.junos import Device

    devices = {}
    observations = []
    opened = []
    try:
        for endpoint in profile["qfx_pair"]:
            role = endpoint["role"]
            address = endpoint["management_address"]
            print("Connecting read-only to %s at %s:%s..." % (role, address, port))
            fingerprint = provisioner_base.ssh_host_key_fingerprint(address, port)
            dev = Device(
                host=address,
                user=username,
                passwd=password,
                port=port,
                gather_facts=True,
            )
            dev.open(auto_probe=10, hostkey_verify=False)
            devices[role] = dev
            opened.append(dev)
            observations.append(observe_qfx(dev, role, address, fingerprint))
        return devices, observations, opened
    except Exception:
        for dev in reversed(opened):
            try:
                dev.close()
            except Exception:
                pass
        raise


def _site_init(argv):
    parser = argparse.ArgumentParser(prog="migrate site-init")
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--site-id")
    parser.add_argument("--environment", choices=("lab", "production"))
    parser.add_argument("--qfx-a")
    parser.add_argument("--qfx-b")
    parser.add_argument("--management-vlan-id", type=int)
    parser.add_argument("--management-vlan-name")
    parser.add_argument("--recovery-vlan-id", type=int)
    parser.add_argument("--recovery-vlan-name")
    parser.add_argument("--prestage-vlan-id", type=int)
    parser.add_argument("--prestage-vlan-name")
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--ae-min", type=int)
    parser.add_argument("--ae-max", type=int)
    parser.add_argument("--lacp-system-id-base")
    args = parser.parse_args(argv)

    settings = load_settings(args.settings)
    path = profile_path(settings)
    if path.is_file():
        print("Existing site profile: %s" % path)
        if input("Replace this site profile? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("Site initialization cancelled; existing profile unchanged.")
            return 1

    site_id = _prompt(args.site_id, "Site ID", "campus")
    environment = _prompt(args.environment, "Environment (lab/production)", "lab").lower()
    if environment not in ("lab", "production"):
        raise SiteError("environment must be lab or production")
    qfx_a = _prompt(args.qfx_a, "QFX-A management address")
    qfx_b = _prompt(args.qfx_b, "QFX-B management address")
    if not qfx_a or not qfx_b:
        raise SiteError("both QFX management addresses are required")

    mgmt_name = _prompt(args.management_vlan_name, "Management VLAN name", "MGMT")
    mgmt_id = _prompt_int(args.management_vlan_id, "Management VLAN ID", 163)
    recovery_name = _prompt(args.recovery_vlan_name, "Temporary recovery VLAN name", "TEMP-RECOVERY")
    recovery_id = _prompt_int(args.recovery_vlan_id, "Temporary recovery VLAN ID", 3999)
    prestage_name = _prompt(args.prestage_vlan_name, "EX-only prestage/default VLAN name", "TEMP-ACCESS")
    prestage_id = _prompt_int(args.prestage_vlan_id, "EX-only prestage/default VLAN ID", 3998)
    ae_min = _prompt_int(args.ae_min, "First AE number available for migration staging", 0)
    ae_max = _prompt_int(args.ae_max, "Last AE number available for migration staging", 127)
    lacp_base = _prompt(
        args.lacp_system_id_base,
        "LACP system-ID base for ae0 (last octet becomes AE number)",
        "02:00:00:00:00:00",
    )

    excluded = list(args.exclude)
    if not excluded:
        raw = input("QFX ET interfaces to exclude/reserve (comma-separated, blank for none): ").strip()
        if raw:
            excluded = [item.strip() for item in raw.split(",") if item.strip()]

    value = build_profile(
        site_id,
        environment,
        qfx_a,
        qfx_b,
        {"name": mgmt_name, "vlan_id": mgmt_id},
        {"name": recovery_name, "vlan_id": recovery_id},
        {"name": prestage_name, "vlan_id": prestage_id},
        excluded,
        ae_min,
        ae_max,
        lacp_base,
    )

    print("\nSite initialization")
    print("  Site: %s" % value["site_id"])
    print("  Environment: %s" % value["environment"].upper())
    print("  Production eligible: %s" % ("YES" if value["production_eligible"] else "NO"))
    print("  QFX-A: %s" % qfx_a)
    print("  QFX-B: %s" % qfx_b)
    print("  QFX baseline VLANs: %s (%s), %s (%s)" % (mgmt_name, mgmt_id, recovery_name, recovery_id))
    print("  EX-only prestage VLAN: %s (%s)" % (prestage_name, prestage_id))
    print("  LACP system-ID base: %s" % value["lacp_system_id_base"])
    print("  Voice VLAN: DISCOVERED PER MIGRATION FROM EX4300")
    print("  QFX model/hostname/attachment ports: DISCOVERED, NOT OPERATOR ENTERED")
    print("  Explicitly excluded ET interfaces: %s" % (", ".join(excluded) if excluded else "none"))

    if input("\nCreate this site profile? [y/N]: ").strip().lower() not in ("y", "yes"):
        print("Site profile was not created.")
        return 1
    destination = write_profile(settings, value)
    print("\nSite profile: %s" % destination)
    print("Next action: ./migrate site-discover")
    return 0


def _site_discover(argv):
    parser = argparse.ArgumentParser(prog="migrate site-discover")
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--no-host-key-check", action="store_true")
    args = parser.parse_args(argv)
    settings = load_settings(args.settings)
    profile, _ = load_profile(settings)
    username, password = _credentials(args)

    opened = []
    try:
        _devices, observations, opened = _connect_pair(
            profile, username, password, args.port, args.no_host_key_check
        )
        discovery = build_site_discovery(profile, observations)
    finally:
        for dev in reversed(opened):
            try:
                dev.close()
            except Exception:
                pass

    print("\nQFX site discovery")
    for item in discovery["qfx_pair"]:
        print("  %s: %s | %s | %s" % (item["role"], item["hostname"], item["model"], item["management_address"]))
    print("\nProposed/pre-existing EX attachment staging inventory")
    if discovery["attachment_inventory"]:
        for item in discovery["attachment_inventory"]:
            print("  %-14s -> %-6s  %s" % (item["physical_interface"], item["ae_interface"], item["mapping_source"]))
    else:
        print("  none")
    if discovery["blocked_interfaces"]:
        print("\nConfigured/reserved/incompatible ET interfaces (will NOT be changed)")
        for item in discovery["blocked_interfaces"]:
            print("  %-14s %s" % (item["physical_interface"], item["reason"]))
    asymmetric = discovery["asymmetric_interfaces"]
    if asymmetric["qfx-a-only"] or asymmetric["qfx-b-only"]:
        print("\nAsymmetric physical inventory")
        print("  qfx-a only: %s" % (", ".join(asymmetric["qfx-a-only"]) or "none"))
        print("  qfx-b only: %s" % (", ".join(asymmetric["qfx-b-only"]) or "none"))

    if not discovery["attachment_inventory"]:
        raise SiteError("site discovery found no compatible ET attachment interfaces to stage")
    print("\nNo QFX configuration has been changed.")
    if input("Approve this discovered QFX identity and staging plan? [y/N]: ").strip().lower() not in ("y", "yes"):
        print("Site discovery was not approved; no site artifact created.")
        return 1
    discovery["approval"] = {
        "approved": True,
        "approved_at": utc_now(),
        "scope": "observed-qfx-identity-and-ex-attachment-staging-plan",
    }
    directory, value, action = write_site_discovery(settings, profile, discovery)
    print("\nSite discovery: %s (%s)" % (value["discovery_id"], action))
    print("  Record: %s" % (directory / "discovery.json"))
    print("Next action: ./migrate site-stage")
    return 0


def _rollback_pair(configs, committed_roles):
    errors = []
    for role in reversed(committed_roles):
        try:
            configs[role].rollback(rb_id=1)
            if configs[role].commit(comment="Rollback failed EX migration site baseline staging", timeout=120) is not True:
                errors.append("%s rollback commit did not return success" % role)
        except Exception as exc:
            errors.append("%s: %s" % (role, exc))
    return errors


def _site_stage(argv):
    parser = argparse.ArgumentParser(prog="migrate site-stage")
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--confirm-minutes", type=int, default=10)
    parser.add_argument("--no-host-key-check", action="store_true")
    args = parser.parse_args(argv)
    if not 1 <= args.confirm_minutes <= 60:
        raise SiteError("--confirm-minutes must be between 1 and 60")

    settings = load_settings(args.settings)
    profile, _ = load_profile(settings)
    discoveries = site_discovery_candidates(settings, profile)
    if not discoveries:
        raise SiteError("no approved site discovery exists; run ./migrate site-discover first")
    discovery = discoveries[0]
    username, password = _credentials(args)

    opened = []
    configs = {}
    locked = []
    committed = []
    commit_confirmed = False
    payload = "\n".join(stage_statements(profile, discovery)) + "\n"
    try:
        devices, observations, opened = _connect_pair(
            profile, username, password, args.port, args.no_host_key_check
        )
        observed_by_role = {item["role"]: item for item in observations}
        bound_by_role = {item["role"]: item for item in discovery["qfx_pair"]}
        for role in ("qfx-a", "qfx-b"):
            observed = observed_by_role[role]
            bound = bound_by_role[role]
            for key in ("hostname", "model", "serial_number", "ssh_host_key_sha256"):
                if observed[key] != bound[key]:
                    raise SiteError("%s identity changed since approved site discovery (%s)" % (role, key))

        from jnpr.junos.utils.config import Config
        diffs = {}
        for role in ("qfx-a", "qfx-b"):
            cu = Config(devices[role])
            configs[role] = cu
            cu.lock()
            locked.append(role)
            if cu.diff():
                raise SiteError("%s already has uncommitted candidate changes" % role)
            cu.load(payload, format="set", merge=True)
            if cu.commit_check() is not True:
                raise SiteError("%s site baseline commit-check did not return PASS" % role)
            diffs[role] = str(cu.diff() or "")

        if diffs["qfx-a"] or diffs["qfx-b"]:
            print("\nQFX site baseline candidate diffs")
            for role in ("qfx-a", "qfx-b"):
                print("\n--- %s ---" % role)
                print(diffs[role].rstrip() or "(no candidate diff)")
            print("\nIntent: every approved ET attachment maps to its AE and carries ONLY management and TEMP-RECOVERY. No voice or endpoint data VLAN is added here.")
            if input("\nApprove exactly these site baseline candidates for commit confirmed on both QFXs? [y/N]: ").strip().lower() not in ("y", "yes"):
                for role in reversed(locked):
                    configs[role].rollback()
                print("Site baseline candidate was not approved; no commit performed.")
                return 1
            for role in ("qfx-a", "qfx-b"):
                if configs[role].commit(
                    confirm=args.confirm_minutes,
                    comment="EX migration site baseline %s" % discovery["discovery_id"],
                    timeout=120,
                ) is not True:
                    raise SiteError("%s commit confirmed did not return success" % role)
                committed.append(role)
            commit_confirmed = True

        validation = {}
        for role in ("qfx-a", "qfx-b"):
            checks, passed = validate_staged_device(devices[role], profile, discovery)
            validation[role] = {"passed": passed, "checks": checks}
            if not passed:
                raise SiteError("%s failed post-stage baseline validation" % role)

        if commit_confirmed:
            for role in ("qfx-a", "qfx-b"):
                if configs[role].commit(
                    comment="Confirm EX migration site baseline %s" % discovery["discovery_id"],
                    timeout=120,
                ) is not True:
                    raise SiteError("%s final site baseline confirmation failed" % role)
            commit_confirmed = False

        inventory = build_site_inventory(profile, discovery, observations, validation)
        directory, inventory, action = write_site_inventory(settings, profile, inventory)
        policy = build_active_policy(profile, inventory, directory / "inventory.json")
        policy_path = write_active_policy(settings, policy)
        print("\nQFX site baseline staging: PASS")
        print("  Site inventory: %s (%s)" % (inventory["inventory_id"], action))
        print("  Staged EX attachment AEs: %d" % len(inventory["attachments"]))
        print("  Baseline VLAN IDs: %s" % ", ".join(str(value) for value in inventory["baseline_vlan_ids"]))
        print("  Voice VLANs on staged AEs: NONE")
        print("  Inventory: %s" % (directory / "inventory.json"))
        print("  Generated active policy: %s" % policy_path)
        print("Next action: begin an EX4300 migration, for example ./migrate sw1203 discover --address <old-switch>")
        return 0
    except SiteError:
        if commit_confirmed and committed:
            errors = _rollback_pair(configs, committed)
            if errors:
                raise SiteError("site staging failed and rollback was incomplete: %s" % "; ".join(errors))
        raise
    except Exception as exc:
        if commit_confirmed and committed:
            errors = _rollback_pair(configs, committed)
            suffix = "; rollback incomplete: %s" % "; ".join(errors) if errors else ""
            raise SiteError("site staging failed: %s%s" % (exc, suffix))
        raise SiteError("site staging failed: %s" % exc)
    finally:
        for role in reversed(locked):
            try:
                configs[role].unlock()
            except Exception:
                pass
        for dev in reversed(opened):
            try:
                dev.close()
            except Exception:
                pass


def _site_status(argv):
    parser = argparse.ArgumentParser(prog="migrate site-status")
    parser.add_argument("--settings", default="config/site.json")
    args = parser.parse_args(argv)
    settings = load_settings(args.settings)
    path = profile_path(settings)
    print("EX4300 -> EX4400 Site Readiness")
    if not path.is_file():
        print("  Site profile: PENDING")
        print("\nNext action: ./migrate site-init")
        return 0
    profile, _ = load_profile(settings)
    discoveries = site_discovery_candidates(settings, profile)
    inventories = site_inventory_candidates(settings, profile)
    active = active_policy_path(settings)
    print("  Site: %s" % profile["site_id"])
    print("  Environment: %s" % profile["environment"].upper())
    print("  Production eligible: %s" % ("YES" if profile["production_eligible"] else "NO"))
    print("  Site profile: COMPLETE")
    print("  QFX discovery: %s" % ("APPROVED" if discoveries else "PENDING"))
    print("  QFX baseline staging: %s" % ("COMPLETE" if inventories else "PENDING"))
    print("  Active generated policy: %s" % ("COMPLETE" if active.is_file() else "PENDING"))
    if inventories:
        inventory = inventories[0][0]
        print("  Staged EX attachment AEs: %d" % len(inventory["attachments"]))
        print("  Baseline VLAN IDs: %s" % ", ".join(str(value) for value in inventory["baseline_vlan_ids"]))
        print("  Voice VLAN baseline: NONE (per-migration discovery)")
    if not discoveries:
        print("\nNext action: ./migrate site-discover")
    elif not inventories or not active.is_file():
        print("\nNext action: ./migrate site-stage")
    else:
        print("\nSite readiness: READY FOR EX4300 MIGRATIONS")
    return 0


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        print("Usage: migrate site-init|site-discover|site-stage|site-status", file=sys.stderr)
        return 2
    try:
        if values[0] == "site-init":
            return _site_init(values[1:])
        if values[0] == "site-discover":
            return _site_discover(values[1:])
        if values[0] == "site-stage":
            return _site_stage(values[1:])
        if values[0] == "site-status":
            return _site_status(values[1:])
        raise SiteError("unknown site command %r" % values[0])
    except (SiteError, OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
