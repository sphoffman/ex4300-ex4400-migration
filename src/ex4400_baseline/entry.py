from __future__ import annotations

import os
import sys

from . import cli
from .netconf_bootstrap import ensure_netconf


_PASSWORD_ENV = "EX4400_BASELINE_SOURCE_PASSWORD"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = cli._parser().parse_args(argv)

    try:
        config = cli.load_config(args.config)
        connection = config["connection"]
        username, password = cli._credentials(
            args.username,
            args.password_env,
            "EX4300/router",
        )

        print("Checking EX4300 NETCONF prerequisite on %s..." % args.ex4300)
        result = ensure_netconf(
            args.ex4300,
            username,
            password,
            netconf_port=int(connection["netconf_port"]),
        )
        if result == "ALREADY_ENABLED":
            print("  NETCONF/%s: already available" % connection["netconf_port"])
        else:
            print("  NETCONF/%s: enabled and reachable" % connection["netconf_port"])

        forwarded = list(argv)
        if args.username is None:
            forwarded.extend(["--username", username])
        if args.password_env is None:
            os.environ[_PASSWORD_ENV] = password
            forwarded.extend(["--password-env", _PASSWORD_ENV])

        return cli.main(forwarded)
    except KeyboardInterrupt:
        print("\nERROR: operator interrupted NETCONF prerequisite check", file=sys.stderr)
        return 130
    except Exception as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2
    finally:
        os.environ.pop(_PASSWORD_ENV, None)


if __name__ == "__main__":
    raise SystemExit(main())
