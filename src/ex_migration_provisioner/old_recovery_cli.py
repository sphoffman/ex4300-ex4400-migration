from __future__ import annotations

# Compatibility shim: the historical command name is retained so existing guided
# workflow routing and immutable artifact paths remain stable. The implementation
# now stages PRE-CUTOVER temporary management on a proven-unused old EX4300 access
# port for the replacement EX4400 fxp0. It no longer rewrites old-switch vme.0.

from .temp_management_cli import main, run


if __name__ == "__main__":
    raise SystemExit(main())
