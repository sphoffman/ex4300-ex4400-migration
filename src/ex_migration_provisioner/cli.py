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
from .render import build_render_manifest, render_pre_stage


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


def package_candidates(migration_root):
    candidates = []
    for package_path in sorted((migration_root / "packages").glob("*/package.json")):
        directory = package_path.parent
        try:
            _verify_integrity(directory, ("package.json", "qfx-preflight.json"))
            package = read_json(package_path)
            if package.get("migration_id") != migration_root.name:
                continue
            candidates.append({"package": package, "package_path": package_path, "directory": directory})
        except (AnalysisError, ProvisioningError):
            continue
    return sorted(candidates, key=lambda item: (item["package"].get("created_at", ""), item["package"].get("package_id", "")), reverse=True)


def choose_package(migration_root, package_id=None):
    candidates = package_candidates(migration_root)
    if package_id:
        candidates = [item for item in candidates if item["package"].get("package_id") == package_id]
    if not candidates:
        suffix = " %s" % package_id if package_id else ""
        raise ProvisioningError("no integrity-valid provisioning package%s was found" % suffix)
    return candidates[0]


def _json_file_digest(value):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return sha256_bytes(data)


def _atomic_text(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    os.replace(str(temporary), str(path))


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


def _write_render(package_directory, manifest, rendered):
    destination = package_directory / "renders" / manifest["render_id"]
    render_path = destination / "render.json"
    config_path = destination / "ex4400-pre-stage.set"
    if render_path.is_file():
        _verify_integrity(destination, ("render.json", "ex4400-pre-stage.set"))
        if read_json(render_path) != manifest or config_path.read_text(encoding="utf-8") != rendered:
            raise ProvisioningError("existing render ID has different content")
        return destination, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    _atomic_text(config_path, rendered)
    atomic_json(render_path, manifest)
    atomic_json(destination / "integrity.json", {
        "render.json": sha256_file(render_path),
        "ex4400-pre-stage.set": sha256_file(config_path),
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


def _provisioning_paths(settings):
    return {
        "site_policy": Path(settings.get("qfx_site_policy", "config/qfx-site-policy.lab.json")),
        "bootstrap": Path(settings.get("bootstrap_profile", "config/bootstrap.lab.example.json")),
        "template": Path(settings["ex4400_template"]),
        "contract": Path(settings["ex4400_template_contract"]),
    }


def _require_paths(paths):
    for path in paths.values():
        if not path.is_file():
            raise ProvisioningError("required provisioning input is missing: %s" % path)


def _verify_package_inputs(selected, settings, migration_root, paths):
    package = selected["package"]
    inputs = package.get("inputs", {})
    current = {
        "settings_digest": sha256_bytes(canonical_bytes(settings)),
        "template_digest": sha256_file(paths["template"]),
        "template_contract_digest": sha256_file(paths["contract"]),
        "site_policy_digest": sha256_file(paths["site_policy"]),
        "bootstrap_profile_digest": sha256_file(paths["bootstrap"]),
    }
    for name, value in current.items():
        if inputs.get(name) != value:
            raise ProvisioningError("provisioning package is stale: %s changed" % name)
    if inputs.get("renderer_version") != __version__:
        raise ProvisioningError("provisioning package is stale: renderer version changed")

    preflight_path = selected["directory"] / "qfx-preflight.json"
    preflight = read_json(preflight_path)
    if sha256_bytes(canonical_bytes(preflight)) != inputs.get("qfx_preflight_digest"):
        raise ProvisioningError("provisioning package QFX preflight digest is invalid")
    declared = [item for item in package.get("artifacts", []) if item.get("path") == "qfx-preflight.json"]
    if len(declared) != 1 or declared[0].get("sha256") != sha256_file(preflight_path):
        raise ProvisioningError("provisioning package QFX preflight artifact binding is invalid")

    plan_matches = [
        item for item in approved_plan_candidates(migration_root)
        if item["plan_digest"] == inputs.get("plan_digest")
        and item["approval_digest"] == inputs.get("plan_approval_digest")
    ]
    if len(plan_matches) != 1:
        raise ProvisioningError("provisioning package no longer resolves to one approved integrity-valid plan")
    return sha256_file(selected["package_path"])


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


def _prepare(args, settings, migration_root):
    selected = choose_approved_plan(migration_root)
    paths = _provisioning_paths(settings)
    if args.site_policy:
        paths["site_policy"] = args.site_policy
    if args.bootstrap:
        paths["bootstrap"] = args.bootstrap
    _require_paths(paths)

    policy = validate_site_policy(read_json(paths["site_policy"]))
    bootstrap = read_json(paths["bootstrap"])
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
        except ProvisioningError:
            raise
        except Exception as exc:
            raise ProvisioningError("QFX read-only connection/preflight failed: %s" % exc)
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
        sha256_bytes(canonical_bytes(settings)), sha256_file(paths["template"]), sha256_file(paths["contract"]),
        policy, sha256_file(paths["site_policy"]), bootstrap, sha256_file(paths["bootstrap"]), preflight,
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


def _render(args, settings, migration_root):
    paths = _provisioning_paths(settings)
    _require_paths(paths)
    selected = choose_package(migration_root, args.package_id)
    package_digest = _verify_package_inputs(selected, settings, migration_root, paths)
    template_text = paths["template"].read_text(encoding="utf-8")
    contract = read_json(paths["contract"])
    rendered, validation = render_pre_stage(template_text, contract, selected["package"], __version__)
    config_digest = sha256_bytes(rendered.encode("utf-8"))
    manifest = build_render_manifest(selected["package"], package_digest, config_digest, validation, __version__)
    destination, action = _write_render(selected["directory"], manifest, rendered)

    print("EX4400 pre-stage render")
    print("  Package: %s" % selected["package"]["package_id"])
    print("  Render: %s (%s)" % (manifest["render_id"], action))
    print("  Static validation: PASS")
    print("  Config: %s" % (destination / "ex4400-pre-stage.set"))
    print("  Device connections authorized: no")
    print("  Device writes authorized: no")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Digest-bound EX4400 provisioning preparation and rendering")
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

    render = subparsers.add_parser("render", help="offline-render a validated EX4400 pre-stage configuration")
    render.add_argument("migration_id")
    render.add_argument("--settings", type=Path, default=Path("config/site.json"))
    render.add_argument("--package-id")

    args = parser.parse_args(argv)

    try:
        settings = load_settings(args.settings)
        migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
        if args.command == "prepare":
            return _prepare(args, settings, migration_root)
        if args.command == "render":
            return _render(args, settings, migration_root)
        raise ProvisioningError("unsupported provisioner command")
    except (AnalysisError, ProvisioningError, OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
