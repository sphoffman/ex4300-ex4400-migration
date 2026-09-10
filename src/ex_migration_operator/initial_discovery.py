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


def _migration_id_from_snapshot(path):
    value = read_json(path)
    migration_id = str(value.get("migration_id") or "").strip()
    if not migration_id:
        raise RuntimeError("new discovery snapshot did not contain a migration ID")
    return migration_id


def _run_collect(values):
    result = subprocess.call([sys.executable, "-m", "ex_migration_discovery.cli", "collect"] + values)
    if result != 0:
        raise RuntimeError("discovery collection exited with status %s" % result)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="migrate discover")
    parser.add_argument("address", nargs="?", help="Reachable address of the old EX4300")
    parser.add_argument("--settings", default="config/site.json")
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--duration", type=int)
    parser.add_argument("--interval", type=int)
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--pause-minutes", type=float, default=0)
    parser.add_argument("--no-host-key-check", action="store_true")
    args = parser.parse_args(argv)

    if args.count < 1:
        parser.error("--count must be at least 1")
    if args.pause_minutes < 0:
        parser.error("--pause-minutes must not be negative")

    address = args.address or input("Old EX4300 reachable address: ").strip()
    if not address:
        parser.error("old EX4300 reachable address must not be empty")

    settings = provisioner_base.load_settings(Path(args.settings))
    snapshot_root = settings.get("snapshot_root", "snapshots")
    before = _snapshot_files(snapshot_root)
    migration_id = None

    common = [address, "--settings", args.settings, "--port", str(args.port)]
    if args.username:
        common += ["--username", args.username]
    if args.password_env:
        common += ["--password-env", args.password_env]
    if args.duration is not None:
        common += ["--duration", str(args.duration)]
    if args.interval is not None:
        common += ["--interval", str(args.interval)]
    if args.no_host_key_check:
        common.append("--no-host-key-check")

    for index in range(args.count):
        if args.count > 1:
            print("\nDiscovery collection %d of %d" % (index + 1, args.count))
        values = list(common)
        if migration_id:
            values += ["--migration-id", migration_id]
        _run_collect(values)

        after = _snapshot_files(snapshot_root)
        created = sorted(after - before)
        if not created:
            raise RuntimeError("discovery succeeded but no new immutable snapshot was found")
        newest = created[-1]
        observed_id = _migration_id_from_snapshot(newest)
        if migration_id is None:
            migration_id = observed_id
            print("\nDiscovered migration ID: %s" % migration_id)
        elif observed_id != migration_id:
            raise RuntimeError(
                "subsequent collection derived migration ID %r instead of %r"
                % (observed_id, migration_id)
            )
        before = after

        if index + 1 < args.count and args.pause_minutes:
            seconds = int(round(args.pause_minutes * 60))
            print("Waiting %d seconds before the next independent collection..." % seconds)
            time.sleep(seconds)

    print("\nInitial discovery complete.")
    print("Migration ID: %s" % migration_id)
    print("Continue with: ./migrate %s" % migration_id)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        raise SystemExit(2)
