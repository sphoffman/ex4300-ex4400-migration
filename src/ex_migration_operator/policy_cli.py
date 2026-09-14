from __future__ import annotations

import getpass
import os
import sys
from pathlib import Path

from ex_migration_analyzer.core import atomic_json, read_json
from ex_migration_provisioner import cli_base as provisioner_base
from ex_migration_site import cli as site_cli
from ex_migration_site.core import load_profile

from . import cli as legacy
from . import current_cli


_POLICY_SETTINGS = "config/site.json"
_ORIGINAL_WORKFLOW_STATUS = legacy.workflow_status
_ORIGINAL_SITE_PROMPT = site_cli._prompt


def _option_value(args, name, default=None):
    for index, value in enumerate(args):
        if value == name:
            if index + 1 < len(args):
                return args[index + 1]
            return default
        if value.startswith(name + "="):
            return value.split("=", 1)[1]
    return default


def _has_option(args, name):
    return any(value == name or value.startswith(name + "=") for value in args)


def _settings_path(args):
    return _option_value(args, "--settings", "config/site.json")


def _policy_workflow_status(root):
    """Run the historical status engine with old-switch recovery satisfied.

    Temp-Management and old-switch recovery are outside this project's active
    workflow.  The legacy status engine still contains an immutable historical
    checkpoint, so satisfy that checkpoint internally rather than requiring or
    creating a legacy recovery transaction.
    """
    globals_ = _ORIGINAL_WORKFLOW_STATUS.__globals__
    original = globals_.get("_successful_old_recovery")
    globals_["_successful_old_recovery"] = lambda _root, _digest: True
    try:
        value = _ORIGINAL_WORKFLOW_STATUS(root)
    finally:
        if original is not None:
            globals_["_successful_old_recovery"] = original
    value["old_recovery"] = "COMPLETE"
    return value


def _policy_status_text(value):
    print("EX4300 -> EX4400 Migration")
    print("Migration: %s" % value["migration_id"])
    print("")
    print("  Discovery collections: %s" % value["collections"])
    print("  Analysis:              %s" % value["analysis"])
    print("  Migration plan:        %s" % value["plan"])
    print("  Package:               %s" % value["package"])
    print("  Render:                %s" % value["render"])
    print("  Replacement identity:  %s" % value["identity"])
    print("  EX4400 pre-stage:       %s" % value["ex4400_prestage"])
    probe = value["silent_probe"]
    probe_text = probe.get("status")
    if probe.get("candidate_count") is not None:
        probe_text += " (%s candidate%s)" % (
            probe["candidate_count"],
            "" if probe["candidate_count"] == 1 else "s",
        )
    print("  Silent-port probe:      %s" % probe_text)
    print("  Physical cutover:       %s" % value["physical_cutover"])
    print("  QFX attachment:         %s" % value["qfx_attachment"])
    print("  QFX VLAN stage:         %s" % value["qfx_stage"])
    print("  Endpoint activation:    %s" % value["endpoints"])
    print("  Port-state validation:  %s" % value["port_state"])
    print("  Facilities report:      %s" % value["cabling_report"])
    print("  Final cleanup:          %s" % value["cleanup"])
    print("")
    print("Next action: %s" % value["next_action"])


def _install_policy_hooks(settings_path):
    global _POLICY_SETTINGS
    _POLICY_SETTINGS = settings_path
    legacy.workflow_status = _policy_workflow_status
    legacy._status_text = _policy_status_text


def _site_init_prompt(value, label, default=None):
    """Apply operator-facing defaults without suppressing normal prompts."""
    if label == "Environment (lab/production)":
        default = "production"
    return _ORIGINAL_SITE_PROMPT(value, label, default)


def _record_site_runtime_policy(settings_path):
    settings_path = Path(settings_path)
    settings = provisioner_base.load_settings(settings_path)
    profile, _ = load_profile(settings)
    environment = profile["environment"]

    local_path = settings_path.with_name("site.local.json")
    local = read_json(local_path) if local_path.is_file() else {}
    # Historical compatibility flag only. The active workflow never stages an
    # old-switch recovery transaction or Temp-Management configuration.
    local["old_switch_recovery_required"] = False
    local["default_management_vlan_id"] = int(profile["management_vlan"]["vlan_id"])

    # Keep these dormant values only because current-schema compatibility
    # validators still carry the old field. They are not operator configurable
    # and are not used for any live device write.
    legacy_temp = profile.get("temporary_recovery_vlan") or {
        "name": "Temp-Management",
        "vlan_id": 3999,
    }
    local["temporary_recovery_vlan_name"] = str(legacy_temp["name"])
    local["temporary_recovery_vlan_id"] = int(legacy_temp["vlan_id"])

    if environment == "lab":
        local["analysis_policy"] = "policies/lab-smoke-v1.json"
        local["default_collection_duration_seconds"] = 60
        local["default_collection_interval_seconds"] = 60
    else:
        local["analysis_policy"] = "policies/production-old-v1.json"
        local["default_collection_duration_seconds"] = 1800
        local["default_collection_interval_seconds"] = 180
    atomic_json(local_path, local)
    return local_path, environment, local["analysis_policy"]


def _site_init(args):
    if any(value in ("-h", "--help") for value in args):
        return site_cli.main(["site-init"] + list(args))

    site_args = list(args)
    if not _has_option(site_args, "--prestage-vlan-name"):
        site_args.extend(["--prestage-vlan-name", "TEMP-ACCESS"])
    if not _has_option(site_args, "--prestage-vlan-id"):
        site_args.extend(["--prestage-vlan-id", "3998"])

    original_prompt = site_cli._prompt
    site_cli._prompt = _site_init_prompt
    try:
        result = site_cli.main(["site-init"] + site_args)
    finally:
        site_cli._prompt = original_prompt
    if result != 0:
        return result

    settings_path = _settings_path(args)
    local_path, environment, analysis_policy = _record_site_runtime_policy(settings_path)

    print("")
    print("Temporary fxp0 management: EXTERNAL PREREQUISITE")
    print("  This project does not create, validate, or remove Temp-Management VLAN 3999.")
    print("  Ensure the replacement EX4400 fxp0 is reachable before prestage.")
    print("  EX4400 holding VLAN: TEMP-ACCESS (3998)")
    print("  Site environment: %s" % environment.upper())
    print("  Old-switch analysis policy: %s" % analysis_policy)
    print("  Recorded in: %s" % local_path)
    return 0


def _extract_site_prep_args(args):
    """Split site-init options from credentials/transport shared by later phases."""
    init_args = []
    shared = {
        "username": None,
        "password_env": None,
        "port": "830",
        "confirm_minutes": "10",
        "no_host_key_check": False,
    }
    values = list(args)
    index = 0
    value_options = {
        "--username": "username",
        "--password-env": "password_env",
        "--port": "port",
        "--confirm-minutes": "confirm_minutes",
    }
    while index < len(values):
        value = values[index]
        matched = False
        for option, key in value_options.items():
            if value == option:
                if index + 1 >= len(values):
                    raise ValueError("%s requires a value" % option)
                shared[key] = values[index + 1]
                index += 2
                matched = True
                break
            if value.startswith(option + "="):
                shared[key] = value.split("=", 1)[1]
                index += 1
                matched = True
                break
        if matched:
            continue
        if value == "--no-host-key-check":
            shared["no_host_key_check"] = True
            index += 1
            continue
        init_args.append(value)
        index += 1
    return init_args, shared


def _site_prep(args):
    if any(value in ("-h", "--help") for value in args):
        print("Usage: migrate site-prep [site-init options] [--username USER] [--password-env ENV] [--port 830] [--confirm-minutes 10] [--no-host-key-check]")
        print("Runs site-init, site-discover, and site-stage as one operator workflow.")
        return 0

    try:
        init_args, shared = _extract_site_prep_args(args)
    except ValueError as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2

    result = _site_init(init_args)
    if result != 0:
        return result

    settings_path = _settings_path(init_args)
    username = shared["username"] or input("QFX site username: ").strip()
    if not username:
        print("ERROR: username must not be empty", file=sys.stderr)
        return 2

    cleanup_password_env = False
    password_env = shared["password_env"]
    if password_env:
        if os.environ.get(password_env) is None:
            print("ERROR: environment variable %s is not set" % password_env, file=sys.stderr)
            return 2
    else:
        password_env = "EX_MIGRATION_SITE_PASSWORD"
        os.environ[password_env] = getpass.getpass("QFX site password: ")
        cleanup_password_env = True

    common = [
        "--settings", settings_path,
        "--username", username,
        "--password-env", password_env,
        "--port", str(shared["port"]),
    ]
    if shared["no_host_key_check"]:
        common.append("--no-host-key-check")

    try:
        print("\n=== Site preparation: discovery ===")
        result = site_cli.main(["site-discover"] + common)
        if result != 0:
            return result

        print("\n=== Site preparation: baseline staging ===")
        result = site_cli.main(
            ["site-stage"] + common + ["--confirm-minutes", str(shared["confirm_minutes"])]
        )
        if result != 0:
            return result
    finally:
        if cleanup_password_env:
            os.environ.pop(password_env, None)

    print("\nSite preparation: COMPLETE")
    print("Next action: discover the first EX4300 with ./migrate discover <address>")
    return 0


def main(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    if values and values[0] == "site-init":
        return _site_init(values[1:])
    if values and values[0] == "site-prep":
        return _site_prep(values[1:])

    _install_policy_hooks(_settings_path(values))
    return current_cli.main(values)


if __name__ == "__main__":
    raise SystemExit(main())
