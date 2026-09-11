#!/usr/bin/env python3
"""Python-native operator launcher for environments already running PyEZ.

This mirrors the root ``migrate`` shell wrapper without creating another Docker
container. It is intended for the PyEZ utility container and other environments
where the repository is already mounted locally and the Python dependencies are
installed.
"""

from __future__ import annotations

import getpass
import importlib
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Several workflow phases intentionally launch child Python processes with
# ``sys.executable -m <module>``. In the Docker wrapper, PYTHONPATH is supplied
# by the container invocation. When already inside a PyEZ container, propagate
# the repository source path through the process environment so every child
# process imports the same checkout as this launcher.
_existing_pythonpath = os.environ.get("PYTHONPATH", "")
_pythonpath_entries = [item for item in _existing_pythonpath.split(os.pathsep) if item]
if str(SRC) not in _pythonpath_entries:
    os.environ["PYTHONPATH"] = os.pathsep.join([str(SRC)] + _pythonpath_entries)

os.chdir(str(ROOT))

MIGRATION_COMMANDS = {
    "status",
    "analyze",
    "build",
    "prestage",
    "cutover-ready",
    "cutover",
    "activate",
    "validate",
    "finalize",
    "mac",
}
SITE_COMMANDS = {"site-discover", "site-stage", "site-status"}
OPERATOR_MODULE = "ex_migration_operator.policy_cli"


def _has_option(args, name):
    return any(value == name or value.startswith(name + "=") for value in args)


def _option_value(args, name):
    for index, value in enumerate(args):
        if value == name:
            if index + 1 < len(args):
                return args[index + 1]
            return None
        if value.startswith(name + "="):
            return value.split("=", 1)[1]
    return None


def _help_requested(args):
    return any(value in ("-h", "--help") for value in args)


def _discovery_credentials(args, option_start):
    """Append one ephemeral discovery credential set when the CLI did not supply it."""
    if _help_requested(args):
        return args

    values = list(args)
    scoped = values[option_start:]
    if not _has_option(scoped, "--username"):
        username = input("Username: ").strip()
        if not username:
            raise RuntimeError("username must not be empty")
        values += ["--username", username]

    password_env = _option_value(scoped, "--password-env")
    if password_env:
        if os.environ.get(password_env) is None:
            raise RuntimeError("environment variable %s is not set" % password_env)
        return values

    password = getpass.getpass("Password: ")
    env_name = "EX_MIGRATION_DISCOVERY_PASSWORD"
    os.environ[env_name] = password
    values += ["--password-env", env_name]
    return values


def _route(argv):
    args = list(argv)
    module_name = OPERATOR_MODULE
    initial_discovery = False

    if args:
        first = args[0]
        if first in ("site-init", "site-prep"):
            module_name = OPERATOR_MODULE
        elif first in SITE_COMMANDS:
            module_name = "ex_migration_site.cli"
        elif first == "discover":
            module_name = "ex_migration_operator.initial_discovery"
            initial_discovery = True
            args = args[1:]
        elif first in MIGRATION_COMMANDS:
            print("ERROR: %r is a migration command, not a migration ID." % first, file=sys.stderr)
            print("Use: python migrate.py <migration-id> %s" % first, file=sys.stderr)
            if first == "status":
                print("For site readiness, use: python migrate.py site-status", file=sys.stderr)
            return None, None, 2

    # Match the shell wrapper's bare-resume site readiness gate.
    if (
        module_name == OPERATOR_MODULE
        and len(args) == 1
        and args[0] not in ("site-init", "site-prep")
    ):
        if not (ROOT / "config" / "qfx-site-policy.active.json").is_file():
            print("Migration %r is waiting on site readiness." % args[0])
            print("Complete the site prerequisite before continuing this migration.")
            print("")
            module_name = "ex_migration_site.cli"
            args = ["site-status"]

    discovery_session = False
    option_start = 0
    if initial_discovery:
        discovery_session = True
        option_start = 0
    elif (
        module_name == OPERATOR_MODULE
        and len(args) >= 2
        and args[1] == "discover"
    ):
        discovery_session = True
        option_start = 2

    if discovery_session:
        try:
            args = _discovery_credentials(args, option_start)
        except RuntimeError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return None, None, 2

    return module_name, args, None


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    module_name, args, error = _route(values)
    if error is not None:
        return error
    module = importlib.import_module(module_name)
    return int(module.main(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
