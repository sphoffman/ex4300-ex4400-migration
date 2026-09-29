from __future__ import annotations

import getpass
import os
import sys

from . import cli
from .core import BaselineError, load_config
from .netconf_bootstrap import ensure_netconf


def main(argv=None):
    args = cli._parser().parse_args(argv)
    config = load_config(args.config)
    connection = config["connection"]

    username = str(args.username or input("EX4300/router username: ")).strip()
    if not username:
        print("ERROR: EX4300/router username cannot be empty", file=sys.stderr)
        return 2
    if args.password_env:
        if args.password_env not in os.environ:
            print("ERROR: EX4300/router password environment variable %s is not set" % args.password_env, file=sys.stderr)
            return 2
        password = os.environ[args.password_env]
    else:
        password = getpass.getpass("EX4300/router password: ")
    if not password:
        print("ERROR: EX4300/router password cannot be empty", file=sys.stderr)
        return 2

    try:
        port = int(connection["netconf_port"])
        print("Checking EX4300 NETCONF prerequisite on %s..." % args.ex4300)
        state = ensure_netconf(args.ex4300, username, password, netconf_port=port)
        if state == "ALREADY_ENABLED":
            print("  NETCONF/%s: already available" % port)
        else:
            print("  NETCONF/%s: enabled and reachable" % port)
    except BaselineError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2

    os.environ["EX4400_BASELINE_SOURCE_PASSWORD"] = password
    forwarded = [args.ex4300, "--config", str(args.config), "--username", username,
                 "--password-env", "EX4400_BASELINE_SOURCE_PASSWORD"]
    if args.port:
        forwarded += ["--port", args.port]
    if args.ex4400_username:
        forwarded += ["--ex4400-username", args.ex4400_username]
    if args.ex4400_password_env:
        forwarded += ["--ex4400-password-env", args.ex4400_password_env]
    if args.dry_run:
        forwarded.append("--dry-run")
    try:
        return cli.main(forwarded)
    finally:
        os.environ.pop("EX4400_BASELINE_SOURCE_PASSWORD", None)
