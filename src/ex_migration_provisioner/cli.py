from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ex_migration_analyzer.core import sha256_file, utc_now

from . import cli_base as base


def _bound_transport(identity):
    connection = identity.get("observed", {}).get("connection", {})
    logical_address = str(connection.get("address") or "")
    transport_address = str(
        connection.get("transport_address") or logical_address
    )
    port = int(connection.get("port", 830))
    if not logical_address:
        raise base.ProvisioningError(
            "approved bootstrap identity has no logical management address"
        )
    if not transport_address:
        raise base.ProvisioningError(
            "approved bootstrap identity has no transport address"
        )
    return logical_address, transport_address, port


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
            "approved migration plan has no source-switch hostname; "
            "bootstrap identity cannot be safely distinguished from the old switch"
        )
    return hostname


def _reject_source_switch(migration_root, observed):
    old_hostname = _planned_old_hostname(migration_root)
    observed_hostname = str(
        observed.get("device", {}).get("hostname") or ""
    ).strip()
    if not observed_hostname:
        raise base.ProvisioningError(
            "bootstrap target hostname could not be observed"
        )
    if observed_hostname.lower() == old_hostname.lower():
        raise base.ProvisioningError(
            "bootstrap target hostname %r matches the approved migration source "
            "switch hostname; refusing to bind or use the old EX4300 as the "
            "new-switch target" % observed_hostname
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
        "  1. Rerun prepare %s to refresh the read-only QFX preflight and package."
        % migration_id,
        "  2. Rerun render %s to create a new digest-bound render."
        % migration_id,
    ]
    if bootstrap_changed:
        lines.append(
            "  3. Rerun identify %s because the bootstrap profile changed."
            % migration_id
        )
        lines.append(
            "  4. Retry run with the new render and newly approved identity."
        )
    else:
        lines.append(
            "  3. Retry run with the new render ID, or omit --render-id to "
            "select the newest valid render."
        )
        lines.append(
            "  The existing approved bootstrap identity may be reused; run will "
            "still revalidate its host key and chassis identity."
        )
    lines.extend([
        "  Discovery, analyzer, and planner do not need to be rerun unless their "
        "own inputs changed.",
        "  Existing stale packages/renders remain immutable history; do not edit "
        "or delete them to recover.",
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
        manifest_renderer = (
            selected_render["manifest"].get("inputs", {}).get("renderer_version")
        )
    else:
        selected_render = None
        manifest_renderer = None

    selected_package = base.choose_package(migration_root, package_id)
    changed = _package_stale_inputs(
        selected_package["package"], settings, paths
    )
    if selected_render is not None and manifest_renderer != base.RENDERER_VERSION:
        changed.append("render_renderer_version")
    if changed:
        raise _stale_recovery_error(migration_id, changed)
    return selected_package, selected_render


def _identify_parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-provisioner identify",
        description=(
            "Read-only observe and operator-bind the bootstrap EX4400 identity. "
            "For vJunos labs, --transport-address may name the reachable "
            "containerlab management endpoint while fxp0 remains 10.0.0.15."
        ),
    )
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument(
        "--transport-address",
        help=(
            "LAB ONLY: reachable transport endpoint for vJunos/vrnetlab; "
            "does not change the logical fxp0 address in the bootstrap profile"
        ),
    )
    return parser


def _identify(argv):
    args = _identify_parser().parse_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = (
        Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    )
    paths = base._provisioning_paths(settings)
    if args.bootstrap:
        paths["bootstrap"] = args.bootstrap
    base._require_paths(paths)
    bootstrap = base.read_json(paths["bootstrap"])
    if bootstrap.get("environment") != "lab":
        raise base.ProvisioningError(
            "--transport-address and interactive bootstrap identity enrollment "
            "are currently restricted to lab profiles"
        )

    logical_address = str(bootstrap["fxp0_management_ip"])
    transport_address = str(args.transport_address or logical_address)
    allow_vjunos_switch = bool(
        args.transport_address and transport_address != logical_address
    )
    username, password = base._credentials(args, "EX4400")
    fingerprint = base.ssh_host_key_fingerprint(transport_address, args.port)

    from jnpr.junos import Device

    dev = Device(
        host=transport_address,
        user=username,
        passwd=password,
        port=args.port,
        gather_facts=True,
    )
    try:
        dev.open(auto_probe=10, hostkey_verify=False)
        observed = base.observe_ex4400_identity(
            dev,
            logical_address,
            args.port,
            fingerprint,
            allow_vjunos_switch=allow_vjunos_switch,
        )
        observed["connection"]["transport_address"] = transport_address
        _reject_source_switch(migration_root, observed)
    except base.ProvisioningError:
        raise
    except Exception as exc:
        raise base.ProvisioningError(
            "EX4400 bootstrap identity observation failed: %s" % exc
        )
    finally:
        try:
            dev.close()
        except Exception:
            pass

    print("\nEX4400 bootstrap identity observation")
    print("  Logical fxp0: %s" % logical_address)
    print("  Transport endpoint: %s:%s" % (transport_address, args.port))
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
        "\nThis record pins the logical fxp0 identity, reachable transport "
        "endpoint, SSH host key, and chassis identity required for a live write."
    )
    answer = input(
        "Bind exactly this bootstrap identity to migration %s? [y/N]: "
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
    destination, identity, action = base._write_identity(
        migration_root, identity
    )
    print("\nBootstrap identity: %s (%s)" % (identity["identity_id"], action))
    print("  Identity: %s" % (destination / "identity.json"))
    print("  Eligibility: LAB_ONLY")
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
    migration_root = (
        Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    )
    _provisioning_artifact_precheck(
        args.migration_id,
        settings,
        migration_root,
        bootstrap_override=args.bootstrap,
        render_id=args.render_id,
    )
    selected = base.choose_identity(migration_root, args.identity_id)
    _reject_source_switch(migration_root, selected["identity"]["observed"])
    logical_address, transport_address, bound_port = _bound_transport(
        selected["identity"]
    )
    return args, logical_address, transport_address, bound_port


def _render_precheck(argv):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("migration_id")
    parser.add_argument("--settings", type=Path, default=Path("config/site.json"))
    parser.add_argument("--package-id")
    args, _unknown = parser.parse_known_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = (
        Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    )
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
        raise base.ProvisioningError(
            "--port does not match the transport port pinned by identify"
        )

    # Normal hardware uses the logical fxp0 address directly. Only a lab identity
    # that explicitly pinned a different transport endpoint needs redirection.
    if transport_address == logical_address:
        return base.main(["run"] + argv)

    print("\nPinned lab transport")
    print("  Logical fxp0: %s" % logical_address)
    print("  Transport endpoint: %s:%s" % (transport_address, bound_port))
    print("  Source: approved bootstrap identity (run accepts no override)")

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
