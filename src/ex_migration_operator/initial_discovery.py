from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from ex_migration_analyzer.core import read_json
from ex_migration_provisioner import cli_base as provisioner_base


def _snapshot_files(snapshot_root):
    base = Path(snapshot_root) / "migrations"
    if not base.is_dir():
        return set()
    return {
        path.resolve()
        for path in base.glob("*/old-switch/collections/*/snapshot.json")
        if "_pending_" not in path.parent.name
    }


def _snapshot_identity(path):
    value = read_json(path)
    migration_id = str(value.get("migration_id") or "").strip()
    if not migration_id:
        raise RuntimeError("new discovery snapshot did not contain a migration ID")
    address = str(
        value.get("management", {}).get("connection_address")
        or value.get("connection_address")
        or ""
    ).strip()
    return migration_id, address


def _run_collect(values):
    result = subprocess.call([sys.executable, "-m", "ex_migration_discovery.cli", "collect"] + values)
    if result != 0:
        raise RuntimeError("discovery collection exited with status %s" % result)


def _created_migrations(paths):
    result = {}
    for path in sorted(paths):
        migration_id, address = _snapshot_identity(path)
        result.setdefault(migration_id, address)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(prog="migrate discover")
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("address", nargs="?", help="Reachable address of one old EX4300")
    source.add_argument("--host", action="append", help="Old-switch address; repeat for multiple switches")
    source.add_argument(
        "--inventory",
        type=Path,
        help=(
            "CSV inventory with old_address and optional per-host settings: "
            "new_fxp_address,duration,interval,port,management_vlan,no_host_key_check"
        ),
    )
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--duration", type=int)
    parser.add_argument("--interval", type=int)
    parser.add_argument("--port", type=int)
    parser.add_argument("--management-vlan", type=int)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--pause-minutes", type=float, default=0)
    parser.add_argument("--no-host-key-check", action="store_true", default=None)
    args = parser.parse_args(argv)

    if args.count < 1:
        parser.error("--count must be at least 1")
    if args.pause_minutes < 0:
        parser.error("--pause-minutes must not be negative")

    interactive_single = not args.address and not args.host and not args.inventory
    address = args.address
    if interactive_single:
        address = input("Old EX4300 reachable address: ").strip()
        if not address:
            parser.error("old EX4300 reachable address must not be empty")

    settings = provisioner_base.load_settings(Path(args.settings))
    snapshot_root = settings.get("snapshot_root", "snapshots")
    before = _snapshot_files(snapshot_root)
    first_single_id = None
    discovered = {}

    common = ["--settings", args.settings]
    if address:
        common.insert(0, address)
    elif args.host:
        for host in args.host:
            common += ["--host", host]
    elif args.inventory:
        common += ["--inventory", str(args.inventory)]

    if args.username:
        common += ["--username", args.username]
    if args.password_env:
        common += ["--password-env", args.password_env]
    if args.duration is not None:
        common += ["--duration", str(args.duration)]
    if args.interval is not None:
        common += ["--interval", str(args.interval)]
    if args.port is not None:
        common += ["--port", str(args.port)]
    if args.management_vlan is not None:
        common += ["--management-vlan", str(args.management_vlan)]
    if args.workers is not None:
        common += ["--workers", str(args.workers)]
    if args.no_host_key_check:
        common.append("--no-host-key-check")

    single_target = bool(address) and not args.host and not args.inventory

    for index in range(args.count):
        if args.count > 1:
            print("\nDiscovery collection %d of %d" % (index + 1, args.count))
        values = list(common)
        if single_target and first_single_id:
            values += ["--migration-id", first_single_id]
        _run_collect(values)

        after = _snapshot_files(snapshot_root)
        created = after - before
        if not created:
            raise RuntimeError("discovery succeeded but no new immutable snapshot was found")
        current = _created_migrations(created)
        discovered.update(current)

        if single_target:
            if len(current) != 1:
                raise RuntimeError("single-host discovery created an unexpected number of migration IDs")
            observed_id = next(iter(current))
            if first_single_id is None:
                first_single_id = observed_id
                print("\nDiscovered migration ID: %s" % first_single_id)
            elif observed_id != first_single_id:
                raise RuntimeError(
                    "subsequent collection derived migration ID %r instead of %r"
                    % (observed_id, first_single_id)
                )
        before = after

        if index + 1 < args.count and args.pause_minutes:
            seconds = int(round(args.pause_minutes * 60))
            print("Waiting %d seconds before the next independent collection..." % seconds)
            time.sleep(seconds)

    print("\nInitial discovery complete.")
    if single_target:
        print("Migration ID: %s" % first_single_id)
        print("Continue with: ./migrate %s" % first_single_id)
    else:
        print("Discovered migrations:")
        for migration_id in sorted(discovered):
            address_text = discovered[migration_id] or "address recorded in snapshot"
            print("  %-16s -> %s" % (address_text, migration_id))
        print("\nContinue with:")
        for migration_id in sorted(discovered):
            print("  ./migrate %s" % migration_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        raise SystemExit(2)
