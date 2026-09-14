from __future__ import annotations

"""Current operator entry point with current site-policy semantics installed."""

from ex_migration_site.current_cli import install_current_site_policy

from . import policy_cli as legacy


def main(argv=None):
    install_current_site_policy()
    return legacy.main(argv)
