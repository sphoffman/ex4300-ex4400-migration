from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

from ex_migration_analyzer.core import sha256_file, utc_now

from . import cli_base as base
from .prestage import (
    build_pre_stage_package,
    choose_package_compat,
    package_candidates_compat,
    validate_pre_cutover_site_policy,
    verify_package_inputs_compat,
    write_pre_stage_package,
)


# Keep legacy package support for immutable historical 1.0 artifacts, while all
# new pre-cutover packages use schema 1.1 and contain no live QFX preflight.
if not hasattr(base, "_verify_package_inputs_legacy"):
    base._verify_package_inputs_legacy = base._verify_package_inputs
base.package_candidates = package_candidates_compat
base.choose_package = choose_package_compat
base._verify_package_inputs = verify_package_inputs_compat


def _bound_transport(identity):
    """Return the approved connection endpoint, with legacy transport fallback."""
    connection = identity.get("observed", {}).get("connection", {})
    address = str(connection.get("address") or "")
    transport_address = str(connection.get("transport_address") or address)
    port = int(connection.get("port", 830))
    if not address:
        raise base.ProvisioningError("approved bootstrap identity has no OOB management address")
    if not transport_address:
        raise base.ProvisioningError("approved bootstrap identity has no reachable connection address")
    return address, transport_address, port


def _planned_old_hostname(migration_root):
    selected = base.choose_approved_plan(migration_root)
    hostname = str(
        selected.get("plan", {})
        .get("template_variables", {})
        .get("old_hostname")
        or ""
    ).strip()
    if not hostname:
        raise base.ProvisioningError(
            "approved migration plan has no source-switch hostname; bootstrap identity cannot be safely distinguished from the old switch"
        )
    return hostname


def _reject_source_switch(migration_root, observed):
    old_hostname = _planned_old_hostname(migration_root)
    observed_hostname = str(observed.get("device", {}).get("hostname") or "").strip()
    if not observed_hostname:
        raise base.ProvisioningError("bootstrap target hostname could not be observed")
    if observed_hostname.lower() == old_hostname.lower():
        raise base.ProvisioningError(
            "bootstrap target hostname %r matches the approved migration source switch hostname; refusing to bind or use the old EX4300 as the new-switch target"
            % observed_hostname
        )
    return True


def _current_package_inputs(settings, paths):
    return {
        "settings_digest": base.sha256_bytes(base.canonical_bytes(settings)),
        "template_digest": base.sha256_file(paths["template"]),
        "template_contract_digest": base.sha256_file(paths["contract"]),
        "site_policy_digest": base.sha256_file(paths["site_policy"]),
        "bootstrap_profile_digest": base.sha256_file(paths["bootstrap"]),
    }


def _package_stale_inputs(package, settings, paths):
    inputs = package.get("inputs", {})
    changed = [
        name
        for name, value in _current_package_inputs(settings, paths).items()
        if inputs.get(name) != value
    ]
    if inputs.get("renderer_version") != base.RENDERER_VERSION:
        changed.append("renderer_version")
    return changed


def _stale_recovery_error(migration_id, changed):
    changed = sorted(set(changed))
    bootstrap_changed = "bootstrap_profile_digest" in changed
    lines = [
        "provisioning artifacts are stale: %s changed" % ", ".join(changed),
        "",
        "Recovery:",
        "  1. Rerun prepare %s to rebuild the offline pre-cutover package." % migration_id,
        "     prepare does not connect to the QFX pair; QFX attachment is discovered only after cutover.",
        "  2. Rerun render %s to create a new digest-bound render." % migration_id,
    ]
    if bootstrap_changed:
        lines.append("  3. Rerun identify %s because the bootstrap profile changed." % migration_id)
        lines.append("  4. Retry run with the new render and newly approved identity.")
    else:
        lines.append(
            "  3. Retry run with the new render ID, or omit --render-id to select the newest valid render."
        )
        lines.append(
            "  The existing approved bootstrap identity may be reused; run will still revalidate its host key and chassis identity."
        )
    lines.extend([
        "  Discovery, analyzer, and planner do not need to be rerun unless their own inputs changed.",
        "  Existing stale packages/renders remain immutable history; do not edit or delete them to recover.",
    ])
    return base.ProvisioningError("\n".join(lines))


def _provisioning_artifact_precheck(
    migration_id,
    settings,
    migration_root,
    bootstrap_override=None,
    render_id=None,
    package_id=None,
):
    paths = base._provisioning_paths(settings)
    if bootstrap_override:
        paths["bootstrap"] = bootstrap_override
    base._require_paths(paths)

    if render_id is not None:
        selected_render = base.choose_render(migration_root, render_id)
        package_id = selected_render["manifest"].get("package_id")
        manifest_renderer = selected_render["manifest"].get("inputs", {}).get("renderer_version")
    else:
        selected_render = None
        manifest_renderer = None

    selected_package = base.choose_package(migration_root, package_id)
    changed = _package_stale_inputs(selected_package["package"], settings, paths)
    if selected_render is not None and manifest_renderer != base.RENDERER_VERSION:
        changed.append("render_renderer_version")
    if changed:
        raise _stale_recovery_error(migration_id, changed)
    return selected_package, selected_render


def _prepare_parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner prepare",
        description=(
            "Offline-build the EX4400 pre-cutover package from the approved migration plan, "
            "bootstrap profile, template contract, and static site policy. No QFX connection "
            "or migration attachment discovery occurs in this phase."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--site-policy", type=Path)
    parser.add_argument("--bootstrap", type=Path)
    return parser


def _prepare(argv):
    args = _prepare_parser().parse_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    selected = base.choose_approved_plan(migration_root)

    paths = base._provisioning_paths(settings)
    if args.site_policy:
        paths["site_policy"] = args.site_policy
    if args.bootstrap:
        paths["bootstrap"] = args.bootstrap
    base._require_paths(paths)

    policy = validate_pre_cutover_site_policy(base.read_json(paths["site_policy"]))
    bootstrap = base.read_json(paths["bootstrap"])
    base._validate_input_alignment(settings, policy, bootstrap)

    package = build_pre_stage_package(
        selected["plan"],
        selected["plan_digest"],
        selected["approval"],
        selected["approval_digest"],
        base.sha256_bytes(base.canonical_bytes(settings)),
        base.sha256_file(paths["template"]),
        base.sha256_file(paths["contract"]),
        policy,
        base.sha256_file(paths["site_policy"]),
        bootstrap,
        base.sha256_file(paths["bootstrap"]),
        base.RENDERER_VERSION,
        created_at=utc_now(),
    )
    destination, action = write_pre_stage_package(migration_root, package)

    print("EX4400 pre-cutover package preparation")
    print("  QFX connections: not attempted")
    print("  QFX attachment: UNKNOWN until post-cutover LLDP discovery")
    print("  LACP force-up: prohibited by site policy")
    print("\nProvisioning package: %s (%s)" % (package["package_id"], action))
    print("Plan: %s" % selected["plan"]["plan_id"])
    print("Eligibility: %s" % package["eligibility"]["status"])
    print("Package: %s" % (destination / "package.json"))
    print("Rendering allowed by package contract: yes")
    print("Device writes authorized: no")
    return 0


def _identify_parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner identify",
        description=(
            "Read-only observe and operator-bind the replacement EX4400 identity and the "
            "migration OOB address that will later become the old EX4300 VME recovery address."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument(
        "--oob-address",
        required=True,
        help="authoritative replacement OOB IPv4 address/prefix, for example 10.255.3.18/24",
    )
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    return parser


def _identify(argv):
    args = _identify_parser().parse_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    paths = base._provisioning_paths(settings)
    if args.bootstrap:
        paths["bootstrap"] = args.bootstrap
    base._require_paths(paths)
    bootstrap = base.read_json(paths["bootstrap"])
    environment = str(bootstrap.get("environment") or "")
    if environment not in ("lab", "production"):
        raise base.ProvisioningError("bootstrap profile environment must be lab or production")

    try:
        oob = ipaddress.ip_interface(str(args.oob_address))
    except ValueError as exc:
        raise base.ProvisioningError("invalid --oob-address: %s" % exc)
    if oob.version != 4:
        raise base.ProvisioningError("--oob-address must be IPv4")
    connection_address = str(oob.ip)

    username, password = base._credentials(args, "EX4400")
    fingerprint = base.ssh_host_key_fingerprint(connection_address, args.port)

    from jnpr.junos import Device

    dev = Device(
        host=connection_address,
        user=username,
        passwd=password,
        port=args.port,
        gather_facts=True,
    )
    try:
        dev.open(auto_probe=10, hostkey_verify=False)
        observed = base.observe_ex4400_identity(
            dev,
            connection_address,
            args.port,
            fingerprint,
            allow_vjunos_switch=(environment == "lab"),
        )
        mgmt_config = dev.cli(
            "show configuration routing-instances mgmt_junos routing-options | display set",
            warning=False,
        ) or ""
        gateway = base.parse_mgmt_junos_default_gateway(mgmt_config)
        observed["oob_management"] = {
            "address": str(oob),
            "routing_instance": "mgmt_junos",
            "default_gateway": gateway,
            "gateway_source": "observed-configured-mgmt_junos-default",
        }
        _reject_source_switch(migration_root, observed)
    except base.ProvisioningError:
        raise
    except Exception as exc:
        raise base.ProvisioningError("EX4400 bootstrap identity observation failed: %s" % exc)
    finally:
        try:
            dev.close()
        except Exception:
            pass

    print("\nEX4400 bootstrap identity observation")
    print("  OOB address: %s" % observed["oob_management"]["address"])
    print("  Connection endpoint: %s:%s" % (connection_address, args.port))
    print("  mgmt_junos default gateway: %s" % observed["oob_management"]["default_gateway"])
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
    print(
        "\nThis record pins the OOB address/prefix, mgmt_junos default gateway, SSH host key, and chassis identity. The same OOB address will later be staged on old-switch vme.0."
    )
    answer = input(
        "Bind exactly this replacement identity and OOB management intent to migration %s? [y/N]: "
        % args.migration_id
    ).strip().lower()
    if answer not in ("y", "yes"):
        print("Bootstrap identity was not approved; no identity artifact created.")
        return 1

    identity = base.build_bootstrap_identity(
        args.migration_id,
        bootstrap,
        sha256_file(paths["bootstrap"]),
        observed,
        utc_now(),
    )
    destination, identity, action = base._write_identity(migration_root, identity)
    print("\nBootstrap identity: %s (%s)" % (identity["identity_id"], action))
    print("  Identity: %s" % (destination / "identity.json"))
    print("  Eligibility: %s" % identity["eligibility"]["status"])
    print("  Device writes performed: no")
    return 0


def _run_selector(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument("--render-id")
    parser.add_argument("--identity-id")
    parser.add_argument("--port", type=int, default=830)
    args, _unknown = parser.parse_known_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    _provisioning_artifact_precheck(
        args.migration_id,
        settings,
        migration_root,
        bootstrap_override=args.bootstrap,
        render_id=args.render_id,
    )
    selected = base.choose_identity(migration_root, args.identity_id)
    _reject_source_switch(migration_root, selected["identity"]["observed"])
    logical_address, transport_address, bound_port = _bound_transport(selected["identity"])
    return args, logical_address, transport_address, bound_port


def _render_precheck(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--package-id")
    args, _unknown = parser.parse_known_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    _provisioning_artifact_precheck(
        args.migration_id,
        settings,
        migration_root,
        package_id=args.package_id,
    )


def _run(argv):
    if "-h" in argv or "--help" in argv:
        return base.main(["run"] + argv)

    args, logical_address, transport_address, bound_port = _run_selector(argv)
    if int(args.port) != int(bound_port):
        raise base.ProvisioningError("--port does not match the connection port pinned by identify")

    # New 1.1 identities use one OOB connection address. Keep the redirect only
    # for immutable legacy 1.0 lab identities that pinned a separate transport.
    if transport_address == logical_address:
        return base.main(["run"] + argv)

    print("\nLegacy pinned lab transport")
    print("  Logical address: %s" % logical_address)
    print("  Transport endpoint: %s:%s" % (transport_address, bound_port))
    print("  Source: historical approved bootstrap identity")

    import jnpr.junos

    original_device = jnpr.junos.Device
    original_fingerprint = base.ssh_host_key_fingerprint
    original_observe = base.observe_ex4400_identity

    def redirected_device(*device_args, **device_kwargs):
        values = list(device_args)
        kwargs = dict(device_kwargs)
        if "host" in kwargs and str(kwargs["host"]) == logical_address:
            kwargs["host"] = transport_address
        elif values and str(values[0]) == logical_address:
            values[0] = transport_address
        return original_device(*values, **kwargs)

    def redirected_fingerprint(host, port=830, timeout=10):
        target = host
        if str(host) == logical_address and int(port) == int(bound_port):
            target = transport_address
        return original_fingerprint(target, port, timeout)

    def observed_with_transport(dev, address, port, host_key_sha256):
        observed = original_observe(
            dev,
            address,
            port,
            host_key_sha256,
            allow_vjunos_switch=True,
        )
        if str(address) == logical_address and int(port) == int(bound_port):
            observed["connection"]["transport_address"] = transport_address
        return observed

    jnpr.junos.Device = redirected_device
    base.ssh_host_key_fingerprint = redirected_fingerprint
    base.observe_ex4400_identity = observed_with_transport
    try:
        return base.main(["run"] + argv)
    finally:
        jnpr.junos.Device = original_device
        base.ssh_host_key_fingerprint = original_fingerprint
        base.observe_ex4400_identity = original_observe


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        return base.main(values)
    command = values[0]
    if command == "discover-attachment":
        from . import attachment_cli
        return attachment_cli.main(values[1:])
    if command == "activate-endpoints":
        from . import endpoint_stage_cli
        return endpoint_stage_cli.main(values[1:])
    if command == "port-state":
        from . import port_state_cli
        return port_state_cli.main(values[1:])
    if command == "stage-old-recovery":
        from . import old_recovery_cli
        return old_recovery_cli.main(values[1:])
    if command == "verify-old-recovery":
        from . import old_recovery_verify_cli
        return old_recovery_verify_cli.main(values[1:])
    if command == "cabling-report":
        from . import cabling_report_cli
        return cabling_report_cli.main(values[1:])
    if command == "cleanup":
        from . import recovery_cleanup_cli
        return recovery_cleanup_cli.main(values[1:])
    if command == "prepare":
        try:
            return _prepare(values[1:])
        except (
            base.AnalysisError,
            base.ProvisioningError,
            base.WriteError,
            OSError,
            ValueError,
        ) as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
    if command == "identify":
        try:
            return _identify(values[1:])
        except (
            base.AnalysisError,
            base.ProvisioningError,
            base.WriteError,
            OSError,
            ValueError,
        ) as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
    if command == "render":
        try:
            _render_precheck(values[1:])
            return base.main(values)
        except (
            base.AnalysisError,
            base.ProvisioningError,
            base.WriteError,
            OSError,
            ValueError,
        ) as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
    if command == "run":
        try:
            return _run(values[1:])
        except (
            base.AnalysisError,
            base.ProvisioningError,
            base.WriteError,
            OSError,
            ValueError,
        ) as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 2
    return base.main(values)


if __name__ == "__main__":
    sys.exit(main())
