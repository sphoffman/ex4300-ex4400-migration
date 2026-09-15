#!/usr/bin/env python3

import argparse
import getpass
import sys
from pathlib import Path

from jnpr.junos import Device
from jnpr.junos.exception import ConnectError
from jnpr.junos.utils.config import Config
from jnpr.junos.exception import ConfigLoadError, CommitError, LockError, UnlockError


def detect_config_format(config_file):
    """
    Detect whether the configuration is Junos 'set' format
    or normal hierarchical/text format.
    """
    with open(config_file, "r") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith(
                ("set ", "delete ", "activate ", "deactivate ", "rename ", "insert ")
            ):
                return "set"

            return "text"

    raise ValueError("Configuration file is empty")


def main():
    parser = argparse.ArgumentParser(
        description="Load and commit a configuration on a Juniper device."
    )

    parser.add_argument(
        "hostname",
        help="Hostname or IP address of the Juniper device"
    )

    parser.add_argument(
        "config_file",
        help="Configuration file to load"
    )

    args = parser.parse_args()

    config_path = Path(args.config_file)

    if not config_path.is_file():
        print(f"ERROR: Configuration file not found: {config_path}")
        sys.exit(1)

    username = admin
    password = admin@123

    try:
        config_format = detect_config_format(config_path)
    except Exception as error:
        print(f"ERROR reading configuration file: {error}")
        sys.exit(1)

    print(f"\nConnecting to {args.hostname}...")

    try:
        with Device(
            host=args.hostname,
            user=username,
            passwd=password
        ) as dev:

            print(
                f"Connected to {dev.facts.get('hostname', args.hostname)} "
                f"({dev.facts.get('model', 'unknown model')})"
            )

            cu = Config(dev)

            try:
                print("Locking configuration...")
                cu.lock()

                print(
                    f"Loading {config_path} "
                    f"(format={config_format}, mode=merge)..."
                )

                cu.load(
                    path=str(config_path),
                    format=config_format,
                    merge=True
                )

                print("Running commit check...")
                cu.commit_check()

                print("Commit check successful.")

                print("Committing configuration...")
                cu.commit(
                    comment=f"Configuration loaded from {config_path.name}"
                )

                print("Commit successful.")

            except (ConfigLoadError, CommitError) as error:
                print(f"\nERROR: {error}")
                print("Rolling back candidate configuration...")

                try:
                    cu.rollback()
                except Exception:
                    pass

                sys.exit(1)

            except LockError as error:
                print(f"\nERROR: Unable to lock configuration: {error}")
                sys.exit(1)

            finally:
                try:
                    cu.unlock()
                except UnlockError:
                    pass

    except ConnectError as error:
        print(f"\nERROR connecting to {args.hostname}: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
