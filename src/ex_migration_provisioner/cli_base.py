from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from ex_migration_analyzer.cli import load_settings
from ex_migration_analyzer.core import (
    AnalysisError,
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
    utc_now,
)

from . import RENDERER_VERSION, __version__
from .core import ProvisioningError, build_package, run_qfx_preflight, validate_site_policy
from .render import build_render_manifest, render_pre_stage, validate_pre_stage_render
from .write import (
    WriteError,
    build_bootstrap_identity,
    observe_ex4400_identity,
    parse_mgmt_junos_default_gateway,
    render_statements,
    ssh_host_key_fingerprint,
    validate_bound_identity,
    validate_running_config,
)


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
                        "plan": plan,
                        "plan_path": plan_path,
                        "plan_digest": plan_digest,
                        "approval": approval,
                        "approval_path": approval_path,
                        "approval_digest": sha256_file(approval_path),
                        "approved_at": approval.get("approved_at", ""),
                    })
        except (AnalysisError, ProvisioningError):
            continue
    return sorted(
        candidates,
        key=lambda item: (item["approved_at"], item["plan"]["plan_id"]),
        reverse=True,
    )


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
            candidates.append({
                "package": package,
                "package_path": package_path,
                "directory": directory,
            })
        except (AnalysisError, ProvisioningError):
            continue
    return sorted(
        candidates,
        key=lambda item: (
            item["package"].get("created_at", ""),
            item["package"].get("package_id", ""),
        ),
        reverse=True,
    )


def choose_package(migration_root, package_id=None):
    candidates = package_candidates(migration_root)
    if package_id:
        candidates = [
            item for item in candidates
            if item["package"].get("package_id") == package_id
        ]
    if not candidates:
        suffix = " %s" % package_id if package_id else ""
        raise ProvisioningError(
            "no integrity-valid provisioning package%s was found" % suffix
        )
    return candidates[0]


def render_candidates(migration_root):
    candidates = []
    pattern = "*/renders/*/render.json"
    for render_path in sorted((migration_root / "packages").glob(pattern)):
        directory = render_path.parent
        try:
            _verify_integrity(directory, ("render.json", "ex4400-pre-stage.set"))
            manifest = read_json(render_path)
            if manifest.get("migration_id") != migration_root.name:
                continue
            candidates.append({
                "manifest": manifest,
                "render_path": render_path,
                "config_path": directory / "ex4400-pre-stage.set",
                "directory": directory,
            })
        except (AnalysisError, ProvisioningError):
            continue
    return sorted(
        candidates,
        key=lambda item: (
            item["manifest"].get("created_at", ""),
            item["manifest"].get("render_id", ""),
        ),
        reverse=True,
    )


def choose_render(migration_root, render_id=None):
    candidates = render_candidates(migration_root)
    if render_id:
        candidates = [
            item for item in candidates
            if item["manifest"].get("render_id") == render_id
        ]
    if not candidates:
        suffix = " %s" % render_id if render_id else ""
        raise ProvisioningError(
            "no integrity-valid EX4400 render%s was found" % suffix
        )
    return candidates[0]


def identity_candidates(migration_root):
    candidates = []
    for identity_path in sorted(
        (migration_root / "bootstrap-identities").glob("*/identity.json")
    ):
        directory = identity_path.parent
        try:
            _verify_integrity(directory, ("identity.json",))
            identity = read_json(identity_path)
            if identity.get("migration_id") != migration_root.name:
                continue
            candidates.append({
                "identity": identity,
                "identity_path": identity_path,
                "directory": directory,
            })
        except (AnalysisError, ProvisioningError):
            continue
    return sorted(
        candidates,
        key=lambda item: (
            item["identity"].get("approved_at", ""),
            item["identity"].get("identity_id", ""),
        ),
        reverse=True,
    )


def choose_identity(migration_root, identity_id=None):
    candidates = identity_candidates(migration_root)
    if identity_id:
        candidates = [
            item for item in candidates
            if item["identity"].get("identity_id") == identity_id
        ]
    if not candidates:
        suffix = " %s" % identity_id if identity_id else ""
        raise ProvisioningError(
            "no integrity-valid approved bootstrap identity%s was found" % suffix
        )
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
        if (
            read_json(package_path) != package
            or read_json(destination / "qfx-preflight.json") != preflight
        ):
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
        if (
            read_json(render_path) != manifest
            or config_path.read_text(encoding="utf-8") != rendered
        ):
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


def _write_identity(migration_root, identity):
    destination = (
        migration_root / "bootstrap-identities" / identity["identity_id"]
    )
    identity_path = destination / "identity.json"
    if identity_path.is_file():
        _verify_integrity(destination, ("identity.json",))
        existing = read_json(identity_path)
        if (
            existing.get("observed") == identity.get("observed")
            and existing.get("bootstrap") == identity.get("bootstrap")
            and existing.get("approval", {}).get("approved") is True
        ):
            return destination, existing, "UNCHANGED"
        raise ProvisioningError("existing bootstrap identity ID has different content")
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(identity_path, identity)
    atomic_json(destination / "integrity.json", {
        "identity.json": sha256_file(identity_path),
    })
    return destination, identity, "CREATED"


def _persist_transaction(directory, transaction, candidate_diff):
    directory.mkdir(parents=True, exist_ok=True)
    diff_path = directory / "candidate.diff"
    tx_path = directory / "transaction.json"
    normalized_diff = candidate_diff
    if normalized_diff and not normalized_diff.endswith("\n"):
        normalized_diff += "\n"
    if diff_path.exists():
        if diff_path.read_text(encoding="utf-8") != normalized_diff:
            raise ProvisioningError("transaction candidate diff changed unexpectedly")
    else:
        _atomic_text(diff_path, normalized_diff)
    atomic_json(tx_path, transaction)
    atomic_json(directory / "integrity.json", {
        "candidate.diff": sha256_file(diff_path),
        "transaction.json": sha256_file(tx_path),
    })


def _validate_input_alignment(settings, policy, bootstrap):
    if int(policy["management_vlan"]["vlan_id"]) != int(
        settings.get("default_management_vlan_id", 163)
    ):
        raise ProvisioningError(
            "QFX policy management VLAN does not match site settings"
        )
    if int(policy["temporary_recovery_vlan"]["vlan_id"]) != int(
        settings.get("temporary_recovery_vlan_id", 3999)
    ):
        raise ProvisioningError(
            "QFX policy temporary recovery VLAN does not match site settings"
        )
    if policy["temporary_recovery_vlan"]["name"] != settings.get(
        "temporary_recovery_vlan_name", "TEMP-RECOVERY"
    ):
        raise ProvisioningError(
            "QFX policy temporary recovery VLAN name does not match site settings"
        )
    if bootstrap.get("environment") != policy.get("environment"):
        raise ProvisioningError(
            "bootstrap profile environment does not match QFX site policy"
        )
    if (
        bootstrap.get("provisioning_mode") in ("asserted", "in-place-lab")
        and bootstrap.get("production_eligible") is not False
    ):
        raise ProvisioningError(
            "lab-only bootstrap mode cannot be production eligible"
        )


def _provisioning_paths(settings):
    return {
        "site_policy": Path(
            settings.get("qfx_site_policy", "config/qfx-site-policy.lab.json")
        ),
        "bootstrap": Path(
            settings.get("bootstrap_profile", "config/bootstrap.lab.example.json")
        ),
        "template": Path(settings["ex4400_template"]),
        "contract": Path(settings["ex4400_template_contract"]),
    }


def _require_paths(paths):
    for path in paths.values():
        if not path.is_file():
            raise ProvisioningError(
                "required provisioning input is missing: %s" % path
            )


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
            raise ProvisioningError(
                "provisioning package is stale: %s changed" % name
            )
    if inputs.get("renderer_version") != RENDERER_VERSION:
        raise ProvisioningError(
            "provisioning package is stale: renderer version changed"
        )

    preflight_path = selected["directory"] / "qfx-preflight.json"
    preflight = read_json(preflight_path)
    if sha256_bytes(canonical_bytes(preflight)) != inputs.get("qfx_preflight_digest"):
        raise ProvisioningError(
            "provisioning package QFX preflight digest is invalid"
        )
    declared = [
        item for item in package.get("artifacts", [])
        if item.get("path") == "qfx-preflight.json"
    ]
    if (
        len(declared) != 1
        or declared[0].get("sha256") != sha256_file(preflight_path)
    ):
        raise ProvisioningError(
            "provisioning package QFX preflight artifact binding is invalid"
        )

    plan_matches = [
        item for item in approved_plan_candidates(migration_root)
        if item["plan_digest"] == inputs.get("plan_digest")
        and item["approval_digest"] == inputs.get("plan_approval_digest")
    ]
    if len(plan_matches) != 1:
        raise ProvisioningError(
            "provisioning package no longer resolves to one approved "
            "integrity-valid plan"
        )
    return sha256_file(selected["package_path"])


def _verify_render_inputs(selected_render, settings, migration_root, paths):
    manifest = selected_render["manifest"]
    if manifest.get("schema_version") != "1.0":
        raise ProvisioningError("unsupported render manifest schema")
    if manifest.get("phase") != "pre_stage":
        raise ProvisioningError("selected render is not an EX4400 pre-stage render")
    if manifest.get("validation", {}).get("result") != "PASS":
        raise ProvisioningError("selected render did not pass static validation")
    if manifest.get("inputs", {}).get("renderer_version") != RENDERER_VERSION:
        raise ProvisioningError("selected render uses a stale renderer version")

    package_selected = choose_package(migration_root, manifest.get("package_id"))
    package_digest = _verify_package_inputs(
        package_selected, settings, migration_root, paths
    )
    if manifest.get("inputs", {}).get("package_digest") != package_digest:
        raise ProvisioningError("render package digest binding is invalid")
    package = package_selected["package"]
    if (
        manifest.get("inputs", {}).get("template_digest")
        != package.get("inputs", {}).get("template_digest")
        or manifest.get("inputs", {}).get("template_contract_digest")
        != package.get("inputs", {}).get("template_contract_digest")
    ):
        raise ProvisioningError("render template bindings are invalid")

    config_path = selected_render["config_path"]
    artifact = [
        item for item in manifest.get("artifacts", [])
        if item.get("path") == "ex4400-pre-stage.set"
    ]
    if len(artifact) != 1 or artifact[0].get("sha256") != sha256_file(config_path):
        raise ProvisioningError("rendered EX4400 config artifact binding is invalid")
    rendered = config_path.read_text(encoding="utf-8")
    validate_pre_stage_render(rendered, package)
    return package_selected, rendered


def _credentials(args, label):
    username = args.username or input("%s username: " % label).strip()
    if not username:
        raise ProvisioningError("%s username must not be empty" % label)
    if args.password_env:
        password = os.environ.get(args.password_env)
        if password is None:
            raise ProvisioningError(
                "environment variable %s is not set" % args.password_env
            )
    else:
        password = getpass.getpass("%s password: " % label)
    return username, password


def _print_preflight(preflight):
    print("\nQFX read-only preflight")
    for item in sorted(preflight["devices"], key=lambda value: value["role"]):
        print("  %s %s (%s) %s -> %s: %s" % (
            item["expected_hostname"],
            item["management_address"],
            item["observed_model"] or "unknown-model",
            item["physical_interface"],
            item["ae_interface"],
            item["result"],
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
        raise ProvisioningError(
            "--no-host-key-check is permitted only by a lab QFX site policy"
        )

    username, password = _credentials(args, "QFX")

    from jnpr.junos import Device

    devices = {}
    opened = []
    try:
        try:
            for device_policy in policy["qfx_pair"]:
                role = device_policy["role"]
                address = device_policy["management_address"]
                print(
                    "Connecting read-only to %s at %s..."
                    % (device_policy["expected_hostname"], address)
                )
                dev = Device(
                    host=address,
                    user=username,
                    passwd=password,
                    port=args.port,
                    gather_facts=True,
                )
                dev.open(
                    auto_probe=10,
                    hostkey_verify=not args.no_host_key_check,
                )
                devices[role] = dev
                opened.append(dev)
            preflight = run_qfx_preflight(policy, args.migration_id, devices)
        except ProvisioningError:
            raise
        except Exception as exc:
            raise ProvisioningError(
                "QFX read-only connection/preflight failed: %s" % exc
            )
    finally:
        for dev in reversed(opened):
            try:
                dev.close()
            except Exception:
                pass

    _print_preflight(preflight)
    if preflight["result"] != "PASS":
        raise ProvisioningError(
            "QFX preflight failed; no provisioning package was created"
        )

    package = build_package(
        selected["plan"],
        selected["plan_digest"],
        selected["approval"],
        selected["approval_digest"],
        sha256_bytes(canonical_bytes(settings)),
        sha256_file(paths["template"]),
        sha256_file(paths["contract"]),
        policy,
        sha256_file(paths["site_policy"]),
        bootstrap,
        sha256_file(paths["bootstrap"]),
        preflight,
        _json_file_digest(preflight),
        RENDERER_VERSION,
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
    package_digest = _verify_package_inputs(
        selected, settings, migration_root, paths
    )
    template_text = paths["template"].read_text(encoding="utf-8")
    contract = read_json(paths["contract"])
    rendered, validation = render_pre_stage(
        template_text,
        contract,
        selected["package"],
        RENDERER_VERSION,
    )
    config_digest = sha256_bytes(rendered.encode("utf-8"))
    manifest = build_render_manifest(
        selected["package"],
        package_digest,
        config_digest,
        validation,
        RENDERER_VERSION,
    )
    destination, action = _write_render(
        selected["directory"], manifest, rendered
    )

    print("EX4400 pre-stage render")
    print("  Package: %s" % selected["package"]["package_id"])
    print("  Render: %s (%s)" % (manifest["render_id"], action))
    print("  Static validation: PASS")
    print("  Config: %s" % (destination / "ex4400-pre-stage.set"))
    print("  Device connections authorized: no")
    print("  Device writes authorized: no")
    return 0


def _identify(args, settings, migration_root):
    paths = _provisioning_paths(settings)
    if args.bootstrap:
        paths["bootstrap"] = args.bootstrap
    _require_paths(paths)
    bootstrap = read_json(paths["bootstrap"])
    if bootstrap.get("environment") != "lab":
        raise ProvisioningError(
            "bootstrap identity enrollment is currently implemented for lab profiles only"
        )

    address = str(bootstrap["fxp0_management_ip"])
    username, password = _credentials(args, "EX4400")
    fingerprint = ssh_host_key_fingerprint(address, args.port)

    from jnpr.junos import Device

    dev = Device(
        host=address,
        user=username,
        passwd=password,
        port=args.port,
        gather_facts=True,
    )
    try:
        dev.open(auto_probe=10, hostkey_verify=False)
        observed = observe_ex4400_identity(
            dev, address, args.port, fingerprint
        )
    except ProvisioningError:
        raise
    except Exception as exc:
        raise ProvisioningError(
            "EX4400 bootstrap identity observation failed: %s" % exc
        )
    finally:
        try:
            dev.close()
        except Exception:
            pass

    print("\nEX4400 bootstrap identity observation")
    print("  Address: %s:%s" % (address, args.port))
    print("  SSH host key: %s" % fingerprint)
    print("  Hostname: %s" % observed["device"]["hostname"])
    print("  Model: %s" % observed["device"]["model"])
    print("  Serial: %s" % observed["device"]["serial_number"])
    print("  VC members:")
    for member in observed["device"]["members"]:
        print("    %s: %s %s %s" % (
            member["member_id"],
            member["status"],
            member["serial_number"],
            member["model"],
        ))
    print("\nThis record becomes the pinned identity required for a live write.")
    answer = input(
        "Bind exactly this bootstrap identity to migration %s? [y/N]: "
        % args.migration_id
    ).strip().lower()
    if answer not in ("y", "yes"):
        print("Bootstrap identity was not approved; no identity artifact created.")
        return 1

    identity = build_bootstrap_identity(
        args.migration_id,
        bootstrap,
        sha256_file(paths["bootstrap"]),
        observed,
        utc_now(),
    )
    destination, identity, action = _write_identity(
        migration_root, identity
    )
    print("\nBootstrap identity: %s (%s)" % (identity["identity_id"], action))
    print("  Identity: %s" % (destination / "identity.json"))
    print("  Eligibility: LAB_ONLY")
    print("  Device writes performed: no")
    return 0


def _running_config_evidence(dev):
    commands = [
        'show configuration | display set | match "^set version "',
        "show configuration system host-name | display set",
        "show configuration system services netconf | display set",
        "show configuration system management-instance | display set",
        "show configuration system syslog | display set",
        "show configuration system ntp | display set",
        "show configuration chassis | display set",
        "show configuration interfaces | display set",
        "show configuration snmp | display set",
        "show configuration forwarding-options | display set",
        "show configuration routing-options | display set",
        "show configuration protocols | display set",
        "show configuration switch-options | display set",
        "show configuration vlans | display set",
    ]
    values = []
    for command in commands:
        values.append(dev.cli(command, warning=False) or "")
    return "\n".join(values)


def _build_transaction(
    args,
    selected_render,
    package_selected,
    identity_selected,
    current_identity,
    candidate_diff,
    approved_at,
):
    manifest = selected_render["manifest"]
    package = package_selected["package"]
    identity = identity_selected["identity"]
    diff_digest = sha256_bytes(candidate_diff.encode("utf-8"))
    key = {
        "migration_id": args.migration_id,
        "render_id": manifest["render_id"],
        "identity_id": identity["identity_id"],
        "candidate_diff_sha256": diff_digest,
        "approved_at": approved_at,
    }
    transaction_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "transaction_id": transaction_id,
        "migration_id": args.migration_id,
        "created_at": approved_at,
        "phase": "pre_stage",
        "tool_version": __version__,
        "inputs": {
            "package_id": package["package_id"],
            "package_digest": sha256_file(package_selected["package_path"]),
            "render_id": manifest["render_id"],
            "render_manifest_digest": sha256_file(selected_render["render_path"]),
            "render_config_digest": sha256_file(selected_render["config_path"]),
            "identity_id": identity["identity_id"],
            "identity_digest": sha256_file(identity_selected["identity_path"]),
            "bootstrap_profile_digest": identity["bootstrap"]["profile_digest"],
        },
        "target": current_identity,
        "candidate": {
            "load_operation": "merge",
            "commit_check": "PASS",
            "diff_sha256": diff_digest,
        },
        "approval": {
            "approved": True,
            "approved_at": approved_at,
            "scope": "exact-candidate-diff",
        },
        "commit": {
            "mode": "confirmed",
            "confirm_minutes": args.confirm_minutes,
            "status": "APPROVED_NOT_COMMITTED",
            "confirmed": False,
        },
        "validation": {
            "result": "PENDING",
            "checks": [],
        },
        "safety": {
            "ex4400_write_authorized": True,
            "qfx_connections_allowed": False,
            "qfx_writes_allowed": False,
            "rollback_on_validation_failure": True,
        },
    }


def _run(args, settings, migration_root):
    if not 1 <= int(args.confirm_minutes) <= 60:
        raise ProvisioningError("--confirm-minutes must be between 1 and 60")

    paths = _provisioning_paths(settings)
    if args.bootstrap:
        paths["bootstrap"] = args.bootstrap
    _require_paths(paths)
    bootstrap = read_json(paths["bootstrap"])
    if bootstrap.get("environment") != "lab":
        raise ProvisioningError(
            "EX4400 live pre-stage writes are currently enabled for lab profiles only"
        )

    selected_render = choose_render(migration_root, args.render_id)
    package_selected, rendered = _verify_render_inputs(
        selected_render, settings, migration_root, paths
    )
    identity_selected = choose_identity(migration_root, args.identity_id)
    identity = identity_selected["identity"]
    bootstrap_digest = sha256_file(paths["bootstrap"])
    if identity.get("bootstrap", {}).get("profile_digest") != bootstrap_digest:
        raise ProvisioningError(
            "approved bootstrap identity is stale: bootstrap profile changed"
        )

    bound_connection = identity["observed"]["connection"]
    address = str(bound_connection.get("address") or "").strip()
    if not address:
        raise ProvisioningError("approved bootstrap identity has no OOB connection address")
    if int(bound_connection.get("port")) != int(args.port):
        raise ProvisioningError(
            "bootstrap identity SSH/NETCONF port does not match --port"
        )

    username, password = _credentials(args, "EX4400")
    current_fingerprint = ssh_host_key_fingerprint(address, args.port)
    if current_fingerprint != bound_connection.get("ssh_host_key_sha256"):
        raise ProvisioningError(
            "EX4400 SSH host key changed; refusing to open a write session"
        )

    from jnpr.junos import Device
    from jnpr.junos.utils.config import Config

    dev = Device(
        host=address,
        user=username,
        passwd=password,
        port=args.port,
        gather_facts=True,
    )
    cu = None
    locked = False
    commit_confirmed_started = False
    transaction = None
    transaction_dir = None
    candidate_diff = ""

    try:
        dev.open(auto_probe=10, hostkey_verify=False)
        current_identity = observe_ex4400_identity(
            dev,
            address,
            args.port,
            current_fingerprint,
            allow_vjunos_switch=(bootstrap.get("environment") == "lab"),
        )
        validate_bound_identity(
            current_identity, identity, bootstrap_digest
        )
        print("\nEX4400 target identity: PASS")
        print("  OOB address: %s:%s" % (address, args.port))
        print("  Hostname: %s" % current_identity["device"]["hostname"])
        print("  Model: %s" % current_identity["device"]["model"])
        print("  Serial: %s" % current_identity["device"]["serial_number"])
        print("  SSH host key: pinned and matched")
        print("  Render: %s" % selected_render["manifest"]["render_id"])
        print("  QFX connections/writes: disabled")

        cu = Config(dev)
        cu.lock()
        locked = True
        payload = "\n".join(render_statements(rendered)) + "\n"
        cu.load(payload, format="set", merge=True)
        if cu.commit_check() is not True:
            raise ProvisioningError("EX4400 commit check did not return PASS")
        raw_diff = cu.diff()
        if not raw_diff:
            evidence = _running_config_evidence(dev)
            validate_running_config(rendered, evidence)
            print("\nEX4400 pre-stage configuration is already present.")
            print("No candidate diff exists; no commit was performed.")
            return 0

        candidate_diff = str(raw_diff)
        diff_digest = sha256_bytes(candidate_diff.encode("utf-8"))
        print("\nEX4400 candidate diff")
        print("  SHA256: %s" % diff_digest)
        print("  Load operation: merge")
        print("  Commit check: PASS")
        print("\n%s" % candidate_diff.rstrip())
        answer = input(
            "\nApprove exactly this candidate diff for commit confirmed? [y/N]: "
        ).strip().lower()
        if answer not in ("y", "yes"):
            cu.rollback()
            print("Candidate diff was not approved; no commit was performed.")
            return 1

        approved_at = utc_now()
        transaction = _build_transaction(
            args,
            selected_render,
            package_selected,
            identity_selected,
            current_identity,
            candidate_diff,
            approved_at,
        )
        transaction_dir = (
            migration_root / "transactions" / transaction["transaction_id"]
        )
        _persist_transaction(transaction_dir, transaction, candidate_diff)

        comment = "EX migration %s pre-stage %s" % (
            args.migration_id,
            transaction["transaction_id"],
        )
        committed = cu.commit(
            confirm=args.confirm_minutes,
            comment=comment,
            timeout=120,
        )
        if committed is not True:
            raise ProvisioningError("commit confirmed did not return success")
        commit_confirmed_started = True
        transaction["commit"]["status"] = "CONFIRMED_PENDING_VALIDATION"
        transaction["commit"]["commit_confirmed_at"] = utc_now()
        _persist_transaction(transaction_dir, transaction, candidate_diff)

        try:
            post_fingerprint = ssh_host_key_fingerprint(address, args.port)
            if post_fingerprint != bound_connection.get("ssh_host_key_sha256"):
                raise ProvisioningError(
                    "SSH host key changed after commit confirmed"
                )
            try:
                dev.facts_refresh()
            except Exception:
                pass
            post_identity = observe_ex4400_identity(
                dev,
                address,
                args.port,
                post_fingerprint,
                allow_vjunos_switch=(bootstrap.get("environment") == "lab"),
            )
            validate_bound_identity(
                post_identity,
                identity,
                bootstrap_digest,
                expected_hostname=post_identity["device"]["hostname"],
            )
            evidence = _running_config_evidence(dev)
            validation = validate_running_config(rendered, evidence)
            expected_hostname = package_selected["package"]["variables"]["new_hostname"]
            hostname_line = "set system host-name %s" % expected_hostname
            if hostname_line not in {
                line.strip() for line in evidence.splitlines() if line.strip()
            }:
                raise ProvisioningError(
                    "post-commit hostname configuration is not the planned EX4400 hostname"
                )
            transaction["validation"] = validation
            transaction["validation"]["validated_at"] = utc_now()
            _persist_transaction(transaction_dir, transaction, candidate_diff)
        except Exception as exc:
            transaction["validation"] = {
                "result": "FAIL",
                "checks": [],
                "error": str(exc),
                "validated_at": utc_now(),
            }
            try:
                cu.rollback(rb_id=1)
                rolled_back = cu.commit(
                    comment="Rollback failed EX migration pre-stage %s"
                    % transaction["transaction_id"],
                    timeout=120,
                )
                if rolled_back is not True:
                    raise ProvisioningError(
                        "explicit rollback commit did not return success"
                    )
                transaction["commit"]["status"] = "ROLLED_BACK_AFTER_VALIDATION_FAILURE"
                transaction["commit"]["rollback_at"] = utc_now()
                commit_confirmed_started = False
            except Exception as rollback_exc:
                transaction["commit"]["status"] = "AUTO_ROLLBACK_PENDING"
                transaction["commit"]["rollback_error"] = str(rollback_exc)
            _persist_transaction(transaction_dir, transaction, candidate_diff)
            raise ProvisioningError(
                "post-commit validation failed; rollback status %s: %s"
                % (transaction["commit"]["status"], exc)
            )

        confirmed = cu.commit(
            comment="Confirm EX migration pre-stage %s"
            % transaction["transaction_id"],
            timeout=120,
        )
        if confirmed is not True:
            raise ProvisioningError(
                "final confirmation commit did not return success; confirmed rollback timer remains safety boundary"
            )
        commit_confirmed_started = False
        transaction["commit"]["status"] = "COMMITTED_AND_CONFIRMED"
        transaction["commit"]["confirmed"] = True
        transaction["commit"]["confirmed_at"] = utc_now()
        _persist_transaction(transaction_dir, transaction, candidate_diff)

        print("\nEX4400 pre-stage transaction: PASS")
        print("  Transaction: %s" % transaction["transaction_id"])
        print("  Commit confirmed validation: PASS")
        print("  Final commit confirmation: PASS")
        print("  Record: %s" % (transaction_dir / "transaction.json"))
        print("  QFX connections/writes performed: no")
        return 0
    except ProvisioningError:
        if locked and not commit_confirmed_started and transaction is None:
            try:
                cu.rollback()
            except Exception:
                pass
        raise
    except Exception as exc:
        if locked and not commit_confirmed_started:
            try:
                cu.rollback()
            except Exception:
                pass
        raise ProvisioningError("EX4400 pre-stage write failed: %s" % exc)
    finally:
        if locked:
            try:
                cu.unlock()
            except Exception:
                pass
        try:
            dev.close()
        except Exception:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Digest-bound EX4400 provisioning and guarded pre-stage writes"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser(
        "prepare",
        help="validate approved intent and create a provisioning package",
    )
    prepare.add_argument("migration_id")
    prepare.add_argument("--settings", type=Path, default=Path("config/site.json"))
    prepare.add_argument("--site-policy", type=Path)
    prepare.add_argument("--bootstrap", type=Path)
    prepare.add_argument("--username")
    prepare.add_argument("--password-env")
    prepare.add_argument("--port", type=int, default=830)
    prepare.add_argument(
        "--no-host-key-check",
        action="store_true",
        help="LAB ONLY: disable SSH host-key verification",
    )

    render = subparsers.add_parser(
        "render",
        help="offline-render a validated EX4400 pre-stage configuration",
    )
    render.add_argument("migration_id")
    render.add_argument("--settings", type=Path, default=Path("config/site.json"))
    render.add_argument("--package-id")

    identify = subparsers.add_parser(
        "identify",
        help="read-only observe and operator-bind the bootstrap EX4400 identity",
    )
    identify.add_argument("migration_id")
    identify.add_argument("--settings", type=Path, default=Path("config/site.json"))
    identify.add_argument("--bootstrap", type=Path)
    identify.add_argument("--username")
    identify.add_argument("--password-env")
    identify.add_argument("--port", type=int, default=830)

    run = subparsers.add_parser(
        "run",
        help="apply an approved EX4400 pre-stage render using commit confirmed",
    )
    run.add_argument("migration_id")
    run.add_argument("--settings", type=Path, default=Path("config/site.json"))
    run.add_argument("--bootstrap", type=Path)
    run.add_argument("--render-id")
    run.add_argument("--identity-id")
    run.add_argument("--username")
    run.add_argument("--password-env")
    run.add_argument("--port", type=int, default=830)
    run.add_argument("--confirm-minutes", type=int, default=10)

    args = parser.parse_args(argv)

    try:
        settings = load_settings(args.settings)
        migration_root = (
            Path(settings["snapshot_root"]) / "migrations" / args.migration_id
        )
        if args.command == "prepare":
            return _prepare(args, settings, migration_root)
        if args.command == "render":
            return _render(args, settings, migration_root)
        if args.command == "identify":
            return _identify(args, settings, migration_root)
        if args.command == "run":
            return _run(args, settings, migration_root)
        raise ProvisioningError("unsupported provisioner command")
    except (AnalysisError, ProvisioningError, WriteError, OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
