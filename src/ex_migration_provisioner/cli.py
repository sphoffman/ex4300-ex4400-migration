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
    parser.add_argument("--identity-id")
    parser.add_argument("--port", type=int, default=830)
    args, _unknown = parser.parse_known_args(argv)
    settings = base.load_settings(args.settings)
    migration_root = (
        Path(settings["snapshot_root"]) / "migrations" / args.migration_id
    )
    selected = base.choose_identity(migration_root, args.identity_id)
    _reject_source_switch(migration_root, selected["identity"]["observed"])
    logical_address, transport_address, bound_port = _bound_transport(
        selected["identity"]
    )
    return args, logical_address, transport_address, bound_port


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
