from __future__ import annotations

import sys

from . import qfx_stage_cli


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    if "--plan-only" not in values:
        values.append("--plan-only")
    return qfx_stage_cli.main(values)


if __name__ == "__main__":
    sys.exit(main())
