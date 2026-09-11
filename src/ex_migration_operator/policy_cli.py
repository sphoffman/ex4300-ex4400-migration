from __future__ import annotations

import sys
from pathlib import Path

from ex_migration_analyzer.core import atomic_json, read_json
from ex_migration_provisioner import cli_base as provisioner_base
from ex_migration_site import cli as site_cli

from . import cli as legacy
from . import core as operator_core
from . import current_cli


_POLICY_SETTINGS = "config/site.json"
_ORIGINAL_WORKFLOW_STATUS = legacy.workflow_status
_ORIGINAL_STATUS_TEXT = legacy._status_text


def _option_value(args, name, default=None):
    for index, value in enumerate(args):
        if value == name:
            if index + 1 < len(args):
                return args[index + 1]
            return default
        if value.startswith(name + "="):
            return value.split("=", 1)[1]
    return default


def _settings_path(args):
    return _option_value(args, "--settings", "config/site.json")


def _site_profile_path(settings_path):
    settings = provisioner_base.load_settings(Path(settings_path))
    return Path(settings.get("site_profile", "config/site-profile.json"))


def _old_switch_recovery_required(settings_path):
    path = _site_profile_path(settings_path)
    if not path.is_file():
        return True
    profile = read_json(path)
    # Backward compatibility: profiles created before this policy existed retain
    # the original required-recovery behavior.
    return profile.get("old_switch_recovery_required", True) is not False


def _policy_workflow_status(root):
    if _old_switch_recovery_required(_POLICY_SETTINGS):
        return _ORIGINAL_WORKFLOW_STATUS(root)

    # workflow_status() resolves this helper through the operator_core module at
    # runtime. Temporarily satisfy only this one site-policy-controlled
    # prerequisite so the normal state machine computes every later phase.
    original = operator_core._successful_old_recovery
    operator_core._successful_old_recovery = lambda _root, _digest: True
    try:
        state = _ORIGINAL_WORKFLOW_STATUS(root)
    finally:
        operator_core._successful_old_recovery = original
    state["old_recovery_not_required"] = True
    return state


def _policy_status_text(value):
    if not value.get("old_recovery_not_required"):
        return _ORIGINAL_STATUS_TEXT(value)
    display = dict(value)
    display["old_recovery"] = "NOT_REQUIRED (site policy)"
    return _ORIGINAL_STATUS_TEXT(display)


def _install_policy_hooks(settings_path):
    global _POLICY_SETTINGS
    _POLICY_SETTINGS = settings_path
    legacy.workflow_status = _policy_workflow_status
    legacy._status_text = _policy_status_text


def _site_init(args):
    # Keep normal argparse help side-effect free and unchanged.
    if any(value in ("-h", "--help") for value in args):
        return site_cli.main(["site-init"] + list(args))

    answer = input(
        "Will retired EX4300s remain powered and reachable after cutover for recovery? [Y/n]: "
    ).strip().lower()
    if answer not in ("", "y", "yes", "n", "no"):
        print("ERROR: answer must be yes or no", file=sys.stderr)
        return 2
    recovery_required = answer not in ("n", "no")

    result = site_cli.main(["site-init"] + list(args))
    if result != 0:
        return result

    settings_path = _settings_path(args)
    path = _site_profile_path(settings_path)
    profile = read_json(path)
    profile["old_switch_recovery_required"] = recovery_required
    atomic_json(path, profile)

    print("")
    if recovery_required:
        print("Old-EX recovery policy: REQUIRED")
        print("  Prestage will move the approved replacement OOB address to old EX4300 vme.0.")
    else:
        print("Old-EX recovery policy: NOT REQUIRED")
        print("  Prestage will skip old-EX vme.0 recovery because retired switches are removed/powered down.")
    print("  Recorded in: %s" % path)
    return 0


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == "site-init":
        return _site_init(values[1:])

    _install_policy_hooks(_settings_path(values))
    return current_cli.main(values)


if __name__ == "__main__":
    raise SystemExit(main())
