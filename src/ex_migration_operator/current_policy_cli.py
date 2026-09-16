from __future__ import annotations

"""Current operator entry point with current site-policy semantics installed."""

from ex_migration_site.current_cli import install_current_site_policy

from . import policy_cli as legacy


_ORIGINAL_RUN_MODULE = legacy.legacy._run_module


def _run_current_module(module, args):
    if module == "ex_migration_analyzer.cli":
        module = "ex_migration_analyzer.current_cli"
    return _ORIGINAL_RUN_MODULE(module, args)


def main(argv=None):
    install_current_site_policy()
    legacy.legacy._run_module = _run_current_module
    return legacy.main(argv)
