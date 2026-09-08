from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from ex_migration_analyzer.cli import load_settings
from ex_migration_analyzer.core import AnalysisError, atomic_json, canonical_bytes, read_json, sha256_bytes, sha256_file

from . import __version__
from .core import ProvisioningError, build_package, run_qfx_preflight, validate_site_policy


def _verify_integrity(directory, required):
    integrity_path = directory / "integrity.json"
    if not integrity_path.is_file():
        raise ProvisioningError("missing integrity record: %s" % directory)
    integrity = read_json(integrity_path)
    for name in required:
        path = directory / name
        if not path.is_file() or sha256_file(path) != integrity.get(name):
            raise ProvisioningError("integrity validation failed: %s" % path)


def approved_plan_candidates(migration_root):
    candidates = []
    for plan_path in sorted((migration_root / "plans").glob("*/plan.json")):
        directory = plan_path.parent
        try:
            _verify_integrity(directory, ("plan.json", "report.md"))
            plan = read_json(plan_path)
            if plan.get("migration_id") != migration_root.name:
                continue
            plan_digest = sha256_file(plan_path)
            for approval_path in directory.glob("approvals/*/approval.json"):
                _verify_integrity(approval_path.parent, ("approval.json",))
                approval = read_json(approval_path)
                if (
                    approval.get("migration_id") == plan.get("migration_id")
                    and approval.get("plan_id") == plan.get("plan_id")
                    and approval.get("plan_digest") == plan_digest
                ):
                    candidates.append({
                        "plan": plan, "plan_path": plan_path, "plan_digest": plan_digest,
                        "approval": approval, "approval_path": approval_path,
                        "approval_digest": sha256_file(approval_path), "approved_at": approval.get("approved_at", ""),
                    })
        except (AnalysisError, ProvisioningError):
            continue
    return sorted(candidates, key=lambda item: (item["approved_at"], item["plan"]["plan_id"]), reverse=True)


def choose_approved_plan(migration_root):
    candidates = approved_plan_candidates(migration_root)
    if not candidates:
        raise ProvisioningError("no integrity-valid approved migration plan was found")
    return candidates[0]


def _json_file_digest(value):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return sha256_bytes(data)


def _write_package(migration_root, package, preflight):
    destination = migration_root / "packages" / package["package_id"]
    package_path = destination / "package.json"
    if package_path.is_file():
        _verify_integrity(destination, ("package.json", "qfx-preflight.json"))
        if read_json(package_path) != package or read_json(destination / "qfx-preflight.json") != preflight:
            raise ProvisioningError("existing package ID has different content")
        return destination, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(destination / "qfx-preflight.json", preflight)
    atomic_json(package_path, package)
    atomic_json(destination / "integrity.json", {
        "package.json": sha256_file(package_path),
        "qfx-preflight.json": sha256_file(destination / "qfx-preflight.json"),
    })
    return destination, "CREATED"


def _validate_input_alignment(settings, policy, bootstrap):
    if int(policy["management_vlan"]["vlan_id"]) != int(settings.get("default_management_vlan_id", 163)):
        raise ProvisioningError("QFX policy management VLAN does not match site settings")
    if int(policy["temporary_recovery_vlan"]["vlan_id"]) != int(settings.get("temporary_recovery_vlan_id", 3999)):
        raise ProvisioningError("QFX policy temporary recovery VLAN does not match site settings")
    if policy["temporary_recovery_vlan"]["name"] != settings.get("temporary_recovery_vlan_name", "TEMP-RECOVERY"):
        raise ProvisioningError("QFX policy temporary recovery VLAN name does not match site settings")
    if bootstrap.get("environment") != policy.get("environment"):
        raise ProvisioningError("bootstrap profile environment does not match QFX site policy")
    if bootstrap.get("provisioning_mode") in ("asserted", "in-place-lab") and bootstrap.get("production_eligible") is not False:
        raise ProvisioningError("lab-only bootstrap mode cannot be production eligible")


def _print_preflight(preflight):
    print("\nQFX read-only preflight")
    for item in sorted(preflight["devices"], key=lambda value: value["role"]):
        print("  %s %s (%s) %s -> %s: %s" % (
            item["expected_hostname"], item["management_address"], item["observed_model"] or "unknown-model",
            item["physical_interface"], item["ae_interface"], item["result"],
        ))
        if item["result"] != "PASS":
            for name, passed in item["checks"].items():
                if not passed:
                    print("    FAIL: %s" % name)
    for name, passed in preflight["pair_checks"].items():
        if not passed:
            print("  Pair FAIL: %s" % name)
    print("  Result: %s" % preflight["result"])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Digest-bound EX4400 provisioning preparation")
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser("prepare", help="validate approved intent and create a provisioning package")
    prepare.add_argument("migration_id")
    prepare.add_argument("--settings", type=Path, default=Path("config/site.json"))
    prepare.add_argument("--site-policy", type=Path)
    prepare.add_argument("--bootstrap", type=Path)
    prepare.add_argument("--username")
    prepare.add_argument("--password-env")
    prepare.add_argument("--port", type=int, default=830)
    prepare.add_argument("--no-host-key-check", action="store_true", help="LAB ONLY: disable SSH host-key verification")
    args = parser.parse_args(argv)

    try:
        settings = load_settings(args.settings)
        migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
        selected = choose_approved_plan(migration_root)

        site_policy_path = args.site_policy or Path(settings.get("qfx_site_policy", "config/qfx-site-policy.lab.json"))
        bootstrap_path = args.bootstrap or Path(settings.get("bootstrap_profile", "config/bootstrap.lab.example.json"))
        template_path = Path(settings["ex4400_template"])
        contract_path = Path(settings["ex4400_template_contract"])
        for path in (site_policy_path, bootstrap_path, template_path, contract_path):
            if not path.is_file():
                raise ProvisioningError("required provisioning input is missing: %s" % path)

        policy = validate_site_policy(read_json(site_policy_path))
        bootstrap = read_json(bootstrap_path)
        _validate_input_alignment(settings, policy, bootstrap)
        if args.no_host_key_check and policy["environment"] != "lab":
            raise ProvisioningError("--no-host-key-check is permitted only by a lab QFX site policy")

        username = args.username or input("QFX username: ").strip()
        if not username:
            raise ProvisioningError("QFX username must not be empty")
        if args.password_env:
            password = os.environ.get(args.password_env)
            if password is None:
                raise ProvisioningError("environment variable %s is not set" % args.password_env)
        else:
            password = getpass.getpass("QFX password: ")

        from jnpr.junos import Device

        devices = {}
        opened = []
        try:
            for device_policy in policy["qfx_pair"]:
                role = device_policy["role"]
                address = device_policy["management_address"]
                print("Connecting read-only to %s at %s..." % (device_policy["expected_hostname"], address))
                dev = Device(host=address, user=username, passwd=password, port=args.port, gather_facts=True)
                dev.open(auto_probe=10, hostkey_verify=not args.no_host_key_check)
                devices[role] = dev
                opened.append(dev)
            preflight = run_qfx_preflight(policy, args.migration_id, devices)
        finally:
            for dev in reversed(opened):
                try:
                    dev.close()
                except Exception:
                    pass

        _print_preflight(preflight)
        if preflight["result"] != "PASS":
            raise ProvisioningError("QFX preflight failed; no provisioning package was created")

        package = build_package(
            selected["plan"], selected["plan_digest"], selected["approval"], selected["approval_digest"],
            sha256_bytes(canonical_bytes(settings)), sha256_file(template_path), sha256_file(contract_path),
            policy, sha256_file(site_policy_path), bootstrap, sha256_file(bootstrap_path), preflight,
            _json_file_digest(preflight), __version__,
        )
        destination, action = _write_package(migration_root, package, preflight)
        print("\nProvisioning package: %s (%s)" % (package["package_id"], action))
        print("Plan: %s" % selected["plan"]["plan_id"])
        print("Eligibility: %s" % package["eligibility"]["status"])
        print("Package: %s" % (destination / "package.json"))
        print("Rendering allowed by package contract: yes")
        print("Device writes authorized: no")
        return 0
    except (AnalysisError, ProvisioningError, OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
