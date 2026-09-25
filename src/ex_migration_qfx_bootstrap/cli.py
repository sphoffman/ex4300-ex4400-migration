from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from .core import load_config
from .preflight import build_pair_preflight


class BootstrapError(RuntimeError):
    pass


def _parser():
    parser = argparse.ArgumentParser(
        prog="ex-migration-qfx-bootstrap",
        description="Bootstrap pristine QFX5700 port pairs as deterministic all-active ESI-LAGs.",
    )
    parser.add_argument("--config", type=Path, default=Path("config/qfx5700-esi-bootstrap.json"))
    parser.add_argument("--username")
    parser.add_argument("--password-env")
    parser.add_argument("--port", type=int, default=830)
    parser.add_argument("--dry-run", action="store_true", help="preflight and display changes only")
    parser.add_argument("--confirm-minutes", type=int, default=10)
    parser.add_argument("--no-host-key-check", action="store_true", help="disable NETCONF SSH host-key verification")
    return parser


def _credentials(args):
    username = args.username or input("QFX username: ").strip()
    if not username:
        raise BootstrapError("QFX username is required")
    if args.password_env:
        password = os.environ.get(args.password_env)
        if password is None:
            raise BootstrapError("password environment variable %s is not set" % args.password_env)
    else:
        password = getpass.getpass("QFX password: ")
    return username, password


def _device_by_role(config):
    return {item["role"]: item for item in config["qfx_pair"]}


def _print_preflight(value, config):
    print("\nQFX5700 ESI-LAG Bootstrap Preflight")
    print("  Management VLAN: %s (%s)" % (
        config["management_vlan"]["name"], config["management_vlan"]["vlan_id"]
    ))
    for role in ("qfx-a", "qfx-b"):
        print("  %s online FPCs: %s" % (
            role, ", ".join(str(v) for v in value["fpcs"].get(role, [])) or "NONE"
        ))
        vlan = value["management_vlan"][role]
        print("    Management VLAN: %s" % vlan["result"])
    print("\n  CREATE:          %d" % value["create_count"])
    print("  SKIP_CONFIGURED: %d" % value["skip_count"])
    print("  WARN_ASYMMETRIC: %d" % value["warning_count"])
    for name, passed in value["checks"].items():
        if not passed:
            print("  FAIL: %s" % name)
    for row in value["candidates"]:
        if row["pair_state"] == "WARN_ASYMMETRIC":
            print("  WARN %s -> %s: qfx-a=%s qfx-b=%s" % (
                row["physical_interface"], row["ae_interface"],
                row["devices"]["qfx-a"]["state"], row["devices"]["qfx-b"]["state"],
            ))
    print("\n  Result: %s" % value["result"])


def _payloads(preflight):
    statements = []
    for row in preflight["candidates"]:
        if row["pair_state"] == "CREATE":
            statements.extend(row["devices"]["qfx-a"]["candidate_statements"])
    payload = "\n".join(statements) + ("\n" if statements else "")
    return {"qfx-a": payload, "qfx-b": payload}


def _normalize_diff(value):
    text = str(value or "")
    return text if not text or text.endswith("\n") else text + "\n"


def _rollback(configs, committed_roles):
    errors = []
    for role in ("qfx-b", "qfx-a"):
        if role not in configs:
            continue
        try:
            if role in committed_roles:
                configs[role].rollback(rb_id=1)
                if configs[role].commit(comment="Rollback QFX5700 ESI bootstrap", timeout=120) is not True:
                    raise BootstrapError("rollback commit failed")
            else:
                configs[role].rollback()
        except Exception as exc:
            errors.append("%s: %s" % (role, exc))
    return errors


def run(argv=None):
    args = _parser().parse_args(argv)
    if args.confirm_minutes < 1:
        raise BootstrapError("--confirm-minutes must be at least 1")
    config = load_config(args.config)
    username, password = _credentials(args)
    policies = _device_by_role(config)

    from jnpr.junos import Device
    from jnpr.junos.utils.config import Config

    devices = {}
    opened = []
    configs = {}
    locked = []
    committed = []
    try:
        for role in ("qfx-a", "qfx-b"):
            address = policies[role]["management_address"]
            print("Connecting to %s at %s..." % (role, address))
            dev = Device(host=address, user=username, passwd=password, port=args.port, gather_facts=True)
            dev.open(auto_probe=10, hostkey_verify=not args.no_host_key_check)
            dev.timeout = 120
            devices[role] = dev
            opened.append(dev)

        preflight = build_pair_preflight(devices, config)
        _print_preflight(preflight, config)
        if preflight["result"] != "PASS":
            raise BootstrapError("preflight failed; no configuration changes were made")
        if preflight["create_count"] == 0:
            print("\nNothing to create. No configuration changes were made.")
            return 0

        payloads = _payloads(preflight)
        print("\nCandidate configuration (%d ESI-LAG pairs):" % preflight["create_count"])
        print(payloads["qfx-a"].rstrip())
        if args.dry_run:
            print("\nDry run complete. No configuration changes were made.")
            return 0

        for role in ("qfx-a", "qfx-b"):
            cu = Config(devices[role])
            cu.lock()
            configs[role] = cu
            locked.append(role)
            if cu.diff():
                raise BootstrapError("%s candidate already has uncommitted changes" % role)

        # Re-run all observations after both configuration databases are locked.
        locked_preflight = build_pair_preflight(devices, config)
        if locked_preflight["result"] != "PASS" or _payloads(locked_preflight) != payloads:
            raise BootstrapError("QFX state changed after locks were acquired; refusing to write")

        diffs = {}
        for role in ("qfx-a", "qfx-b"):
            configs[role].load(payloads[role], format="set", merge=True)
            if configs[role].commit_check() is not True:
                raise BootstrapError("%s commit-check failed" % role)
            diffs[role] = _normalize_diff(configs[role].diff())
            if not diffs[role]:
                raise BootstrapError("%s produced an empty candidate diff" % role)

        if diffs["qfx-a"] != diffs["qfx-b"]:
            raise BootstrapError("candidate diffs differ between QFXs; refusing coordinated commit")

        print("\nCandidate diff (identical on both QFXs):\n")
        print(diffs["qfx-a"].rstrip())
        answer = input("\nCommit exactly this configuration to BOTH QFXs? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            for role in reversed(locked):
                configs[role].rollback()
            print("No commit performed.")
            return 1

        for role in ("qfx-a", "qfx-b"):
            if configs[role].commit(
                confirm=args.confirm_minutes,
                comment="QFX5700 deterministic ESI-LAG bootstrap",
                timeout=120,
            ) is not True:
                raise BootstrapError("%s commit confirmed failed" % role)
            committed.append(role)

        # Validate the committed state while commit-confirmed protection is active.
        post = build_pair_preflight(devices, config)
        if post["result"] != "PASS":
            raise BootstrapError("post-commit validation failed")
        expected_created = {
            row["physical_interface"] for row in preflight["candidates"] if row["pair_state"] == "CREATE"
        }
        for row in post["candidates"]:
            if row["physical_interface"] in expected_created:
                a = row["devices"]["qfx-a"]
                b = row["devices"]["qfx-b"]
                if a["physical_config"] == "" or b["physical_config"] == "":
                    raise BootstrapError("post-commit validation did not find expected config on %s" % row["physical_interface"])

        for role in ("qfx-a", "qfx-b"):
            if configs[role].commit(comment="Confirm QFX5700 ESI-LAG bootstrap", timeout=120) is not True:
                raise BootstrapError("%s final confirmation failed" % role)

        print("\nSUCCESS: configured and validated %d ESI-LAG pairs on both QFX5700s." % preflight["create_count"])
        return 0
    except Exception:
        if configs:
            errors = _rollback(configs, committed)
            if errors:
                print("WARNING: rollback errors: %s" % "; ".join(errors), file=sys.stderr)
        raise
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


def main():
    try:
        raise SystemExit(run())
    except (BootstrapError, OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
