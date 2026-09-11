from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .collector import Collector


@dataclass(frozen=True)
class Target:
    host: str
    new_fxp_address: Optional[str] = None
    duration: Optional[int] = None
    interval: Optional[int] = None
    port: Optional[int] = None
    management_vlan: Optional[int] = None
    no_host_key_check: Optional[bool] = None


def _optional_int(row, name, row_number):
    raw = (row.get(name) or "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        raise ValueError("inventory row %d has invalid integer %s=%r" % (row_number, name, raw))


def _optional_bool(row, name, row_number):
    raw = (row.get(name) or "").strip().lower()
    if not raw:
        return None
    if raw in ("1", "true", "yes", "y", "on"):
        return True
    if raw in ("0", "false", "no", "n", "off"):
        return False
    raise ValueError("inventory row %d has invalid boolean %s=%r" % (row_number, name, raw))


def targets_from_csv(path: Path) -> List[Target]:
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or "old_address" not in reader.fieldnames:
            raise ValueError("inventory CSV must contain an old_address column")
        result = []
        for row_number, row in enumerate(reader, start=2):
            host = (row.get("old_address") or "").strip()
            if not host:
                raise ValueError("inventory row %d has no old_address" % row_number)
            management_vlan = _optional_int(row, "management_vlan", row_number)
            if management_vlan is None:
                management_vlan = _optional_int(row, "management_vlan_id", row_number)
            target = Target(
                host=host,
                new_fxp_address=(row.get("new_fxp_address") or "").strip() or None,
                duration=_optional_int(row, "duration", row_number),
                interval=_optional_int(row, "interval", row_number),
                port=_optional_int(row, "port", row_number),
                management_vlan=management_vlan,
                no_host_key_check=_optional_bool(row, "no_host_key_check", row_number),
            )
            if target.duration is not None and target.duration < 0:
                raise ValueError("inventory row %d duration must not be negative" % row_number)
            if target.interval is not None and target.interval < 1:
                raise ValueError("inventory row %d interval must be at least 1" % row_number)
            if target.port is not None and not 1 <= target.port <= 65535:
                raise ValueError("inventory row %d port must be between 1 and 65535" % row_number)
            if target.management_vlan is not None and not 1 <= target.management_vlan <= 4094:
                raise ValueError("inventory row %d management_vlan must be between 1 and 4094" % row_number)
            result.append(target)
        if not result:
            raise ValueError("inventory CSV contains no targets")
        return result


def _resolve(cli_value, row_value, default_value):
    if cli_value is not None:
        return cli_value
    if row_value is not None:
        return row_value
    return default_value


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="cmd", required=True)
    collect = subparsers.add_parser("collect")
    source = collect.add_mutually_exclusive_group(required=False)
    source.add_argument("--host", action="append", help="Old-switch address; repeat for multiple switches")
    source.add_argument(
        "--inventory",
        type=Path,
        help=(
            "CSV inventory. Required column: old_address. Optional per-host columns: "
            "new_fxp_address,duration,interval,port,management_vlan,no_host_key_check"
        ),
    )
    collect.add_argument("address", nargs="?", help="Old-switch address for the normal single-device workflow")
    collect.add_argument("--username")
    collect.add_argument("--output")
    collect.add_argument("--migration-id", help="Optional assertion/override; valid only with one host")
    collect.add_argument("--management-vlan", type=int, default=None)
    collect.add_argument("--password-env")
    collect.add_argument("--duration", type=int, default=None)
    collect.add_argument("--interval", type=int, default=None)
    collect.add_argument("--port", type=int, default=None)
    collect.add_argument("--workers", type=int)
    collect.add_argument("--settings", type=Path, default=Path("config/site.json"))
    collect.add_argument(
        "--no-host-key-check",
        action="store_true",
        default=None,
        help="LAB ONLY: disable SSH host-key verification; CLI overrides inventory rows",
    )
    args = parser.parse_args()

    if args.address and (args.host or args.inventory):
        parser.error("address cannot be combined with --host or --inventory")
    if args.address:
        targets = [Target(args.address)]
    elif args.host:
        targets = [Target(value) for value in args.host]
    elif args.inventory:
        try:
            targets = targets_from_csv(args.inventory)
        except ValueError as exc:
            parser.error(str(exc))
    else:
        address = input("Old-switch address: ").strip()
        if not address:
            parser.error("old-switch address must not be empty")
        targets = [Target(address)]

    if args.migration_id and len(targets) != 1:
        parser.error("--migration-id may be used only with a single host")
    if len({target.host for target in targets}) != len(targets):
        parser.error("duplicate old-switch addresses are not allowed")

    settings = json.loads(args.settings.read_text()) if args.settings.is_file() else {}
    args.output = args.output or settings.get("snapshot_root", "snapshots")
    default_management_vlan = int(settings.get("default_management_vlan_id", 163))
    default_duration = int(settings.get("default_collection_duration_seconds", 1800))
    default_interval = int(settings.get("default_collection_interval_seconds", 60))
    default_port = 830
    workers = args.workers or int(settings.get("collection_workers", 4))
    if workers < 1:
        parser.error("--workers must be at least 1")
    if args.duration is not None and args.duration < 0:
        parser.error("--duration must not be negative")
    if args.interval is not None and args.interval < 1:
        parser.error("--interval must be at least 1")
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.management_vlan is not None and not 1 <= args.management_vlan <= 4094:
        parser.error("--management-vlan must be between 1 and 4094")

    resolved = {}
    for target in targets:
        duration = _resolve(args.duration, target.duration, default_duration)
        interval = _resolve(args.interval, target.interval, default_interval)
        port = _resolve(args.port, target.port, default_port)
        management_vlan = _resolve(args.management_vlan, target.management_vlan, default_management_vlan)
        no_host_key_check = _resolve(args.no_host_key_check, target.no_host_key_check, False)
        resolved[target.host] = {
            "duration": int(duration),
            "interval": int(interval),
            "port": int(port),
            "management_vlan": int(management_vlan),
            "no_host_key_check": bool(no_host_key_check),
            "expected_samples": int(duration) // int(interval) + 1,
        }

    active_workers = min(workers, len(targets))
    print("\nEX migration discovery")
    print("Targets: %d" % len(targets))
    print("Workers: %d" % active_workers)
    if len(targets) == 1:
        policy = resolved[targets[0].host]
        print("Observation duration: %d seconds per switch" % policy["duration"])
        print("Sample interval: %d seconds" % policy["interval"])
        print("Expected samples: %d per switch" % policy["expected_samples"])
    else:
        print("Per-target collection settings:")
        for target in targets:
            policy = resolved[target.host]
            print(
                "  %s | duration=%ss interval=%ss samples=%s port=%s mgmt-vlan=%s host-key-check=%s"
                % (
                    target.host,
                    policy["duration"],
                    policy["interval"],
                    policy["expected_samples"],
                    policy["port"],
                    policy["management_vlan"],
                    "off" if policy["no_host_key_check"] else "on",
                )
            )
    print("Total runtime includes connection and static-discovery overhead.\n")

    username = args.username or input("Username: ").strip()
    if not username:
        parser.error("username must not be empty")
    password = os.environ.get(args.password_env) if args.password_env else getpass.getpass("Password: ")
    if args.password_env and password is None:
        parser.error("environment variable %s is not set" % args.password_env)

    from jnpr.junos import Device

    interactive_status = sys.stdout.isatty()
    status_lock = threading.Lock()
    statuses = {target.host: {"stage": "QUEUED"} for target in targets}

    def update_status(host, stage, details=None):
        details = details or {}
        with status_lock:
            previous = statuses.get(host, {})
            statuses[host] = dict(details, stage=stage)
            if not interactive_status:
                samples = details.get("samples_completed")
                expected = resolved[host]["expected_samples"]
                changed = previous.get("stage") != stage or (
                    samples is not None and samples != previous.get("samples_completed")
                )
                if changed:
                    suffix = " | %s/%s samples" % (samples, expected) if samples is not None else ""
                    print("%s  %s%s" % (host, stage.replace("_", " ").title(), suffix), flush=True)

    def status_line():
        now = time.monotonic()
        parts = []
        with status_lock:
            current = {host: dict(value) for host, value in statuses.items()}
        for host in sorted(current):
            value = current[host]
            stage = value.get("stage", "QUEUED")
            if stage == "OBSERVING":
                remaining = max(0, int(value.get("deadline_monotonic", now) - now + 0.999))
                samples = value.get("samples_completed", 0)
                expected = resolved[host]["expected_samples"]
                parts.append(
                    "%s Observing %02d:%02d %s/%s"
                    % (host, remaining // 60, remaining % 60, samples, expected)
                )
            else:
                parts.append("%s %s" % (host, stage.replace("_", " ").title()))
        return " | ".join(parts)

    def collect_target(target):
        policy = resolved[target.host]
        update_status(target.host, "CONNECTING")
        dev = Device(
            host=target.host,
            user=username,
            passwd=password,
            port=policy["port"],
            gather_facts=True,
        )
        try:
            dev.open(auto_probe=10, hostkey_verify=not policy["no_host_key_check"])
            result = Collector(
                dev,
                Path(args.output),
                policy["duration"],
                policy["interval"],
                args.migration_id,
                management_vlan_id=policy["management_vlan"],
                connection_address=target.host,
                new_fxp_address=target.new_fxp_address,
                progress_callback=lambda stage, details: update_status(target.host, stage, details),
            ).run()
            return target.host, result, None
        except Exception as exc:
            update_status(target.host, "FAILED")
            return target.host, None, exc
        finally:
            try:
                dev.close()
            except Exception:
                pass

    results = []
    with ThreadPoolExecutor(max_workers=active_workers) as executor:
        pending = {executor.submit(collect_target, target) for target in targets}
        while pending:
            done, pending = wait(pending, timeout=1, return_when=FIRST_COMPLETED)
            for future in done:
                results.append(future.result())
            if interactive_status:
                line = status_line()
                print("\r" + line + " " * max(0, 160 - len(line)), end="", flush=True)
    if interactive_status:
        print()

    failures = [item for item in results if item[2] is not None]
    print("\nCollection summary")
    for host, result, error in sorted(results):
        if error:
            print("FAILED   %s  %s: %s" % (host, type(error).__name__, error), file=sys.stderr)
        else:
            print("SUCCESS  %s  %s" % (host, result))
    print("\n%d succeeded, %d failed" % (len(results) - len(failures), len(failures)))
    if failures:
        raise SystemExit(1)

    if len(results) == 1 and results[0][1] is not None:
        path = Path(results[0][1])
        parts = path.parts
        migration_id = None
        try:
            index = parts.index("migrations")
            migration_id = parts[index + 1]
        except (ValueError, IndexError):
            pass
        if migration_id:
            if args.migration_id:
                print("\nMigration ID confirmed: %s" % migration_id)
            else:
                print("\nDiscovered migration ID: %s" % migration_id)
            print("Continue with: ./migrate %s" % migration_id)


if __name__ == "__main__":
    main()
