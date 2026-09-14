from __future__ import annotations

import argparse
import getpass
import os
import sys

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes, sha256_file, utc_now
from ex_migration_provisioner import cli_base as provisioner_base

from . import core as site_core
from .core import (
    SiteError,
    active_policy_path,
    build_profile,
    load_profile,
    load_settings,
    observe_qfx,
    profile_path,
    site_discovery_candidates,
    site_inventory_candidates,
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


def _required_qfx_vlan_ids(profile):
    return [int(profile["management_vlan"]["vlan_id"])]


def _legacy_temp_vlan_id(profile):
    value = profile.get("temporary_recovery_vlan") or {}
    try:
        return int(value.get("vlan_id", 3999))
    except (TypeError, ValueError):
        return 3999


def _build_site_discovery(profile, observations, observed_at=None):
    """Discover only the new QFX topology and permanent management baseline.

    Temp-Management is an external legacy-path prerequisite.  A historical 3999
    membership is tolerated so old lab artifacts do not block discovery, but it
    is never required, staged, or removed by this workflow.
    """
    site_core.validate_profile(profile)
    by_role = {item["role"]: item for item in observations}
    site_core._require(set(by_role) == {"qfx-a", "qfx-b"}, "site discovery requires both QFX observations")
    a = by_role["qfx-a"]
    b = by_role["qfx-b"]
    site_core._require(a["hostname"] and b["hostname"], "QFX hostnames could not be observed")
    site_core._require(a["hostname"].lower() != b["hostname"].lower(), "QFX hostnames must be distinct")
    site_core._require(a["model"] and b["model"], "QFX models could not be observed")

    excluded = set(profile["excluded_interfaces"])
    common = sorted((set(a["interfaces"]) & set(b["interfaces"])) - excluded)
    only_a = sorted(set(a["interfaces"]) - set(b["interfaces"]))
    only_b = sorted(set(b["interfaces"]) - set(a["interfaces"]))

    management_id = int(profile["management_vlan"]["vlan_id"])
    legacy_temp_id = _legacy_temp_vlan_id(profile)
    required_baseline = [management_id]
    tolerated_existing = {management_id, legacy_temp_id}
    definitions_a = site_core._vlan_definitions(a["vlan_config_text"])
    definitions_b = site_core._vlan_definitions(b["vlan_config_text"])
    site_core._require(
        len(definitions_a.get(management_id, set())) == 1,
        "qfx-a does not define exactly one management VLAN ID %s" % management_id,
    )
    site_core._require(
        len(definitions_b.get(management_id, set())) == 1,
        "qfx-b does not define exactly one management VLAN ID %s" % management_id,
    )

    members_a = site_core._ae_members(a["ae_map"])
    members_b = site_core._ae_members(b["ae_map"])
    attachments = []
    blocked = []

    for physical in common:
        ae_a = a["ae_map"].get(physical)
        ae_b = b["ae_map"].get(physical)
        if not ae_a and not ae_b:
            blocked.append({"physical_interface": physical, "reason": "NOT_PREPROVISIONED_TO_AE"})
            continue
        if not ae_a or ae_a != ae_b:
            blocked.append({
                "physical_interface": physical,
                "reason": "ASYMMETRIC_EXISTING_AE",
                "qfx_a_ae": ae_a,
                "qfx_b_ae": ae_b,
            })
            continue

        ae = ae_a
        if len(members_a.get(ae, [])) != 1 or len(members_b.get(ae, [])) != 1:
            blocked.append({
                "physical_interface": physical,
                "reason": "AE_HAS_MULTIPLE_ET_MEMBERS",
                "ae_interface": ae,
                "qfx_a_members": members_a.get(ae, []),
                "qfx_b_members": members_b.get(ae, []),
            })
            continue

        contract_a = site_core._ae_contract(a["interface_config_text"], ae)
        contract_b = site_core._ae_contract(b["interface_config_text"], ae)
        system_a = site_core._lacp_system_id(a["interface_config_text"], ae)
        system_b = site_core._lacp_system_id(b["interface_config_text"], ae)
        structural_ok = all(contract_a.values()) and all(contract_b.values()) and bool(system_a) and system_a == system_b
        if not structural_ok:
            blocked.append({
                "physical_interface": physical,
                "reason": "PREPROVISIONED_AE_CONTRACT_FAILED",
                "ae_interface": ae,
                "qfx_a_checks": contract_a,
                "qfx_b_checks": contract_b,
                "qfx_a_lacp_system_id": system_a,
                "qfx_b_lacp_system_id": system_b,
            })
            continue

        vlan_a = site_core._vlan_ids(a["interface_config_text"], ae, definitions_a)
        vlan_b = site_core._vlan_ids(b["interface_config_text"], ae, definitions_b)
        if vlan_a is None or vlan_b is None:
            blocked.append({
                "physical_interface": physical,
                "reason": "UNRESOLVED_AE_VLAN_MEMBERSHIP",
                "ae_interface": ae,
            })
            continue
        if not set(vlan_a).issubset(tolerated_existing) or not set(vlan_b).issubset(tolerated_existing):
            blocked.append({
                "physical_interface": physical,
                "reason": "EXISTING_AE_HAS_NON_BASELINE_VLANS",
                "ae_interface": ae,
                "qfx_a_vlans": vlan_a,
                "qfx_b_vlans": vlan_b,
            })
            continue

        attachments.append({
            "physical_interface": physical,
            "ae_interface": ae,
            "mapping_source": "PREPROVISIONED_SYMMETRIC",
            "lacp_system_id": system_a,
            "current_vlan_ids": {"qfx-a": vlan_a, "qfx-b": vlan_b},
        })

    key = {
        "site_id": profile["site_id"],
        "profile": profile,
        "qfx": [
            {k: item.get(k) for k in ("role", "management_address", "ssh_host_key_sha256", "hostname", "model", "serial_number")}
            for item in sorted(observations, key=lambda value: value["role"])
        ],
        "attachments": attachments,
        "blocked": blocked,
        "required_qfx_vlan_ids": required_baseline,
    }
    discovery_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.1",
        "discovery_id": discovery_id,
        "site_id": profile["site_id"],
        "observed_at": observed_at or utc_now(),
        "environment": profile["environment"],
        "qfx_pair": key["qfx"],
        "attachment_inventory": attachments,
        "blocked_interfaces": blocked,
        "asymmetric_interfaces": {"qfx-a-only": only_a, "qfx-b-only": only_b},
        "baseline_vlan_ids": required_baseline,
        "approval": {"approved": False},
    }


def _stage_statements(profile, discovery):
    mgmt = profile["management_vlan"]["name"]
    return [
        "set interfaces %s unit 0 family ethernet-switching vlan members %s" % (ae, mgmt)
        for ae in sorted({item["ae_interface"] for item in discovery["attachment_inventory"]})
    ]


def _validate_staged_device(dev, profile, discovery):
    config = dev.cli("show configuration interfaces | display set", warning=False) or ""
    vlan_top = dev.cli("show configuration vlans | display set", warning=False) or ""
    vlan_ri = dev.cli("show configuration routing-instances | display set", warning=False) or ""
    definitions = site_core._vlan_definitions(vlan_top + "\n" + vlan_ri)
    management_id = int(profile["management_vlan"]["vlan_id"])
    legacy_temp_id = _legacy_temp_vlan_id(profile)
    allowed = {management_id, legacy_temp_id}
    mapping = site_core._ae_map(config)
    checks = []
    for item in discovery["attachment_inventory"]:
        physical = item["physical_interface"]
        ae = item["ae_interface"]
        observed_vlans = site_core._vlan_ids(config, ae, definitions)
        observed_system = site_core._lacp_system_id(config, ae)
        contract = site_core._ae_contract(config, ae)
        resolved = observed_vlans is not None
        ids = set(observed_vlans or [])
        checks.append({
            "physical_interface": physical,
            "ae_interface": ae,
            "mapping_matches": mapping.get(physical) == ae,
            "baseline_vlan_ids": observed_vlans,
            "management_vlan_present": management_id in ids,
            "only_supported_preexisting_vlans": resolved and ids <= allowed,
            "lacp_system_id": observed_system,
            "lacp_system_id_matches_discovery": observed_system == item.get("lacp_system_id"),
            "lacp_active": contract["lacp_active"],
            "lacp_force_up_absent": contract["lacp_force_up_absent"],
            "esi_auto": contract["esi_auto_derive_type_1_lacp"],
            "esi_all_active": contract["esi_all_active"],
            "interface_mode_trunk": contract["interface_mode_trunk"],
        })
    passed = all(
        item["mapping_matches"]
        and item["management_vlan_present"]
        and item["only_supported_preexisting_vlans"]
        and item["lacp_system_id_matches_discovery"]
        and item["lacp_active"]
        and item["lacp_force_up_absent"]
        and item["esi_auto"]
        and item["esi_all_active"]
        and item["interface_mode_trunk"]
        for item in checks
    )
    return checks, passed


def _build_site_inventory(profile, discovery, qfx_observations, validation_by_role, created_at=None):
    site_core._require(all(item["passed"] for item in validation_by_role.values()), "QFX management baseline VLAN validation failed")
    attachments = [
        {
            "physical_interface": item["physical_interface"],
            "ae_interface": item["ae_interface"],
            "lacp_system_id": item["lacp_system_id"],
            "baseline_vlan_ids": _required_qfx_vlan_ids(profile),
        }
        for item in discovery["attachment_inventory"]
    ]
    stable_qfx = [
        {k: item.get(k) for k in ("role", "management_address", "ssh_host_key_sha256", "hostname", "model", "serial_number")}
        for item in sorted(qfx_observations, key=lambda value: value["role"])
    ]
    key = {
        "site_id": profile["site_id"],
        "profile": profile,
        "source_discovery_id": discovery["discovery_id"],
        "qfx_pair": stable_qfx,
        "attachments": attachments,
    }
    inventory_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.1",
        "inventory_id": inventory_id,
        "site_id": profile["site_id"],
        "created_at": created_at or utc_now(),
        "environment": profile["environment"],
        "source_discovery_id": discovery["discovery_id"],
        "qfx_pair": stable_qfx,
        "attachments": attachments,
        "baseline_vlan_ids": _required_qfx_vlan_ids(profile),
        "validation": {role: value for role, value in sorted(validation_by_role.items())},
        "result": "PASS",
    }


def _build_active_policy(profile, inventory, inventory_path):
    pair = [
        {
            "role": item["role"],
            "management_address": item["management_address"],
            "expected_hostname": item["hostname"],
            "expected_model": item["model"],
        }
        for item in inventory["qfx_pair"]
    ]
    ports = [item["physical_interface"] for item in inventory["attachments"]]
    ae_numbers = [int(item["ae_interface"][2:]) for item in inventory["attachments"]]
    # temporary_recovery_vlan remains only as dormant schema compatibility
    # metadata for older artifacts.  It is not part of the active QFX baseline
    # and no live path is allowed to stage/remove it.
    return {
        "schema_version": "1.2",
        "site_policy_id": "%s-%s" % (profile["site_id"], inventory["inventory_id"]),
        "site_id": profile["site_id"],
        "environment": profile["environment"],
        "production_eligible": profile["production_eligible"],
        "qfx_pair": pair,
        "stage_port_pools": {"site-verified": ports},
        "excluded_interfaces": list(profile["excluded_interfaces"]),
        "ae_pool": {
            "method": "discover-from-existing-qfx-config",
            "ae_min": min(ae_numbers),
            "ae_max": max(ae_numbers),
            "migration_assignment_prebound": False,
        },
        "management_vlan": dict(profile["management_vlan"]),
        "temporary_recovery_vlan": dict(profile.get("temporary_recovery_vlan") or {"name": "Temp-Management", "vlan_id": 3999}),
        "prestage_access_vlan": dict(profile["prestage_access_vlan"]),
        "precutover_qfx_baseline": {
            "required_vlan_ids": list(inventory["baseline_vlan_ids"]),
            "lacp_mode": "active",
            "force_up": False,
        },
        "esi": {"method": "auto-derive-type-1-lacp", "all_active": True},
        "validation": {
            "attachment_discovered_post_cutover": True,
            "require_interface_symmetry": True,
            "require_lldp": True,
            "require_lacp_partner": True,
            "require_matching_ae": True,
            "require_matching_lacp_system_id": True,
            "operator_supplied_ports_allowed": False,
        },
        "source_site_inventory": {
            "inventory_id": inventory["inventory_id"],
            "inventory_digest": sha256_file(inventory_path),
            "path": str(inventory_path),
        },
    }


def _site_init(argv):
    parser = argparse.ArgumentParser(prog="migrate site-init")
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--site-id")
    parser.add_argument("--environment", choices=("lab", "production"))
    parser.add_argument("--qfx-a")
    parser.add_argument("--qfx-b")
    parser.add_argument("--management-vlan-id", type=int)
    parser.add_argument("--management-vlan-name")
    # Legacy options remain accepted but hidden so old automation does not fail.
    parser.add_argument("--recovery-vlan-id", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--recovery-vlan-name", help=argparse.SUPPRESS)
    parser.add_argument("--prestage-vlan-id", type=int)
    parser.add_argument("--prestage-vlan-name")
    parser.add_argument("--exclude", action="append", default=[])
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
    prestage_name = _prompt(args.prestage_vlan_name, "EX-only prestage/default VLAN name", "TEMP-ACCESS")
    prestage_id = _prompt_int(args.prestage_vlan_id, "EX-only prestage/default VLAN ID", 3998)

    excluded = list(args.exclude)
    if not excluded:
        raw = input("QFX ET interfaces to exclude/reserve (comma-separated, blank for none): ").strip()
        if raw:
            excluded = [item.strip() for item in raw.split(",") if item.strip()]

    # Keep the old profile field only so historical schemas/loaders remain
    # compatible.  It is deliberately not operator configurable and is not used
    # by site discovery/staging or per-migration writes.
    legacy_temp = {"name": "Temp-Management", "vlan_id": 3999}
    value = build_profile(
        site_id,
        environment,
        qfx_a,
        qfx_b,
        {"name": mgmt_name, "vlan_id": mgmt_id},
        legacy_temp,
        {"name": prestage_name, "vlan_id": prestage_id},
        excluded,
    )

    print("\nSite initialization")
    print("  Site: %s" % value["site_id"])
    print("  Environment: %s" % value["environment"].upper())
    print("  Production eligible: %s" % ("YES" if value["production_eligible"] else "NO"))
    print("  QFX-A: %s" % qfx_a)
    print("  QFX-B: %s" % qfx_b)
    print("  Required pre-cutover QFX VLAN: %s (%s)" % (mgmt_name, mgmt_id))
    print("  EX-only prestage VLAN: %s (%s)" % (prestage_name, prestage_id))
    print("  Temporary fxp0 management: EXTERNAL PREREQUISITE (not managed by this project)")
    print("  Voice VLAN: DISCOVERED PER MIGRATION FROM EX4300")
    print("  QFX hostname/model: DISCOVERED")
    print("  QFX ET->AE/LACP/ESI/trunk structure: MUST ALREADY BE PREPROVISIONED")
    print("  This tool may add only missing management VLAN membership during site-stage.")
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
        _devices, observations, opened = _connect_pair(profile, username, password, args.port, args.no_host_key_check)
        discovery = _build_site_discovery(profile, observations)
    finally:
        for dev in reversed(opened):
            try:
                dev.close()
            except Exception:
                pass

    print("\nQFX site discovery")
    for item in discovery["qfx_pair"]:
        print("  %s: %s | %s | %s" % (item["role"], item["hostname"], item["model"], item["management_address"]))
    print("\nPreprovisioned EX attachment inventory")
    if discovery["attachment_inventory"]:
        for item in discovery["attachment_inventory"]:
            current = item["current_vlan_ids"]
            print("  %-14s -> %-6s  VLANs qfx-a=%s qfx-b=%s" % (
                item["physical_interface"], item["ae_interface"], current["qfx-a"], current["qfx-b"]
            ))
    else:
        print("  none")
    if discovery["blocked_interfaces"]:
        print("\nET interfaces not eligible for EX migration use")
        for item in discovery["blocked_interfaces"]:
            print("  %-14s %s" % (item["physical_interface"], item["reason"]))
    asymmetric = discovery["asymmetric_interfaces"]
    if asymmetric["qfx-a-only"] or asymmetric["qfx-b-only"]:
        print("\nAsymmetric physical inventory")
        print("  qfx-a only: %s" % (", ".join(asymmetric["qfx-a-only"]) or "none"))
        print("  qfx-b only: %s" % (", ".join(asymmetric["qfx-b-only"]) or "none"))

    if not discovery["attachment_inventory"]:
        raise SiteError("site discovery found no valid preprovisioned ET-to-AE attachment interfaces")
    print("\nNo QFX configuration has been changed.")
    print("site-stage will only ensure management VLAN membership; it cannot create or repair AE/LACP/ESI structure.")
    print("Temporary fxp0 management is external to this project and is not inspected or changed.")
    if input("Approve this discovered QFX identity and preprovisioned AE inventory? [y/N]: ").strip().lower() not in ("y", "yes"):
        print("Site discovery was not approved; no site artifact created.")
        return 1
    discovery["approval"] = {
        "approved": True,
        "approved_at": utc_now(),
        "scope": "observed-qfx-identity-and-preprovisioned-ae-inventory",
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
            if configs[role].commit(comment="Rollback failed EX migration QFX management baseline staging", timeout=120) is not True:
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
    payload = "\n".join(_stage_statements(profile, discovery)) + "\n"
    try:
        devices, observations, opened = _connect_pair(profile, username, password, args.port, args.no_host_key_check)
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
                raise SiteError("%s site management baseline commit-check did not return PASS" % role)
            diffs[role] = str(cu.diff() or "")

        if diffs["qfx-a"] or diffs["qfx-b"]:
            print("\nQFX pre-cutover management baseline candidate diffs")
            for role in ("qfx-a", "qfx-b"):
                print("\n--- %s ---" % role)
                print(diffs[role].rstrip() or "(no candidate diff)")
            print("\nIntent: add only missing permanent management VLAN membership to already-preprovisioned migration AEs.")
            print("Temporary fxp0 management, AE membership, LACP, system IDs, ESI, and trunk structure are outside this tool's write scope.")
            if input("\nApprove exactly these management-VLAN candidates for commit confirmed on both QFXs? [y/N]: ").strip().lower() not in ("y", "yes"):
                for role in reversed(locked):
                    configs[role].rollback()
                print("Site baseline candidate was not approved; no commit performed.")
                return 1
            for role in ("qfx-a", "qfx-b"):
                if configs[role].commit(
                    confirm=args.confirm_minutes,
                    comment="EX migration pre-cutover QFX management baseline %s" % discovery["discovery_id"],
                    timeout=120,
                ) is not True:
                    raise SiteError("%s commit confirmed did not return success" % role)
                committed.append(role)
            commit_confirmed = True

        validation = {}
        for role in ("qfx-a", "qfx-b"):
            checks, passed = _validate_staged_device(devices[role], profile, discovery)
            validation[role] = {"passed": passed, "checks": checks}
            if not passed:
                raise SiteError("%s failed post-stage QFX management baseline validation" % role)

        if commit_confirmed:
            for role in ("qfx-a", "qfx-b"):
                if configs[role].commit(
                    comment="Confirm EX migration pre-cutover QFX management baseline %s" % discovery["discovery_id"],
                    timeout=120,
                ) is not True:
                    raise SiteError("%s final site baseline confirmation failed" % role)
            commit_confirmed = False

        inventory = _build_site_inventory(profile, discovery, observations, validation)
        directory, inventory, action = write_site_inventory(settings, profile, inventory)
        policy = _build_active_policy(profile, inventory, directory / "inventory.json")
        policy_path = write_active_policy(settings, policy)
        print("\nQFX pre-cutover management baseline: PASS")
        print("  Site inventory: %s (%s)" % (inventory["inventory_id"], action))
        print("  Verified preprovisioned EX attachment AEs: %d" % len(inventory["attachments"]))
        print("  Required VLAN ID on every migration AE: %s" % inventory["baseline_vlan_ids"][0])
        print("  Temporary fxp0 management: EXTERNAL (not part of QFX baseline)")
        print("  Voice/data VLANs on migration AEs: NONE at site baseline")
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
    print("  Preprovisioned QFX AE discovery: %s" % ("APPROVED" if discoveries else "PENDING"))
    print("  QFX management baseline: %s" % ("COMPLETE" if inventories else "PENDING"))
    print("  Active generated policy: %s" % ("COMPLETE" if active.is_file() else "PENDING"))
    print("  Temporary fxp0 management: EXTERNAL PREREQUISITE")
    if inventories:
        inventory = inventories[0][0]
        print("  Verified EX attachment AEs: %d" % len(inventory["attachments"]))
        print("  Baseline VLAN IDs: %s" % ", ".join(str(value) for value in inventory["baseline_vlan_ids"]))
        print("  Voice/data VLAN baseline: NONE (per-migration)")
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
