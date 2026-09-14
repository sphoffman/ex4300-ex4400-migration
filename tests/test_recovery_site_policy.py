from pathlib import Path

from ex_migration_analyzer.core import atomic_json, read_json
from ex_migration_operator import policy_cli


def _settings(tmp_path):
    Path("config").mkdir(exist_ok=True)
    atomic_json(
        Path("config/site.json"),
        {
            "schema_version": "1.3",
            "site_profile": "config/site-profile.json",
        },
    )


def _mock_profile(monkeypatch, environment="lab"):
    monkeypatch.setattr(
        policy_cli,
        "load_profile",
        lambda _settings: (
            {
                "environment": environment,
                "management_vlan": {"name": "v163", "vlan_id": 163},
                "temporary_recovery_vlan": {"name": "Temp-Management", "vlan_id": 3999},
            },
            Path("config/site-profile.json"),
        ),
    )


def test_old_switch_recovery_defaults_required_for_existing_settings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _settings(tmp_path)
    assert policy_cli._old_switch_recovery_required("config/site.json") is True


def test_old_switch_recovery_can_be_disabled_by_local_settings(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _settings(tmp_path)
    atomic_json(
        Path("config/site.local.json"),
        {"old_switch_recovery_required": False},
    )
    assert policy_cli._old_switch_recovery_required("config/site.json") is False


def test_temp_management_checkpoint_is_not_bypassed_when_post_cutover_recovery_disabled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _settings(tmp_path)
    atomic_json(
        Path("config/site.local.json"),
        {"old_switch_recovery_required": False},
    )
    monkeypatch.setattr(
        policy_cli,
        "_ORIGINAL_WORKFLOW_STATUS",
        lambda _root: {"old_recovery": "PENDING", "next_action": "prestage"},
    )
    state = policy_cli._policy_workflow_status(tmp_path / "snapshots/migrations/test")
    assert state["old_recovery"] == "PENDING"
    assert "old_recovery_not_required" not in state


def test_site_init_recovery_disabled_uses_fixed_temp_access_and_lab_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _settings(tmp_path)
    _mock_profile(monkeypatch, "lab")
    captured = []

    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    monkeypatch.setattr(
        policy_cli.site_cli,
        "main",
        lambda argv: captured.append(list(argv)) or 0,
    )

    assert policy_cli._site_init([]) == 0
    assert captured == [[
        "site-init",
        "--prestage-vlan-name", "TEMP-ACCESS",
        "--prestage-vlan-id", "3998",
    ]]
    local = read_json(Path("config/site.local.json"))
    assert local["old_switch_recovery_required"] is False
    assert local["analysis_policy"] == "policies/lab-smoke-v1.json"
    assert local["default_collection_duration_seconds"] == 60
    assert local["default_collection_interval_seconds"] == 60
    assert local["default_management_vlan_id"] == 163
    assert local["temporary_recovery_vlan_name"] == "Temp-Management"
    assert local["temporary_recovery_vlan_id"] == 3999


def test_site_init_production_binds_production_analysis_policy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _settings(tmp_path)
    _mock_profile(monkeypatch, "production")
    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    monkeypatch.setattr(policy_cli.site_cli, "main", lambda _argv: 0)

    assert policy_cli._site_init([]) == 0
    local = read_json(Path("config/site.local.json"))
    assert local["old_switch_recovery_required"] is True
    assert local["analysis_policy"] == "policies/production-old-v1.json"
    assert local["default_collection_duration_seconds"] == 1800
    assert local["default_collection_interval_seconds"] == 180
    assert local["default_management_vlan_id"] == 163
    assert local["temporary_recovery_vlan_name"] == "Temp-Management"
    assert local["temporary_recovery_vlan_id"] == 3999


def test_site_init_recovery_enabled_keeps_temp_access_interactive(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _settings(tmp_path)
    _mock_profile(monkeypatch, "lab")
    captured = []

    monkeypatch.setattr("builtins.input", lambda _prompt: "y")
    monkeypatch.setattr(
        policy_cli.site_cli,
        "main",
        lambda argv: captured.append(list(argv)) or 0,
    )

    assert policy_cli._site_init([]) == 0
    assert captured == [["site-init"]]


def test_site_init_explicit_temp_access_overrides_win_when_recovery_disabled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _settings(tmp_path)
    _mock_profile(monkeypatch, "lab")
    captured = []

    monkeypatch.setattr("builtins.input", lambda _prompt: "n")
    monkeypatch.setattr(
        policy_cli.site_cli,
        "main",
        lambda argv: captured.append(list(argv)) or 0,
    )

    args = [
        "--prestage-vlan-name", "CUSTOM-HOLDING",
        "--prestage-vlan-id", "3000",
    ]
    assert policy_cli._site_init(args) == 0
    assert captured == [["site-init"] + args]


def test_site_init_prompt_defaults_and_labels():
    captured = []
    original = policy_cli._ORIGINAL_SITE_PROMPT
    try:
        policy_cli._ORIGINAL_SITE_PROMPT = (
            lambda value, label, default=None: captured.append((value, label, default)) or str(default)
        )
        assert policy_cli._site_init_prompt(None, "Environment (lab/production)", "lab") == "production"
        assert policy_cli._site_init_prompt(None, "Temporary recovery VLAN name", "TEMP-RECOVERY") == "Temp-Management"
        assert policy_cli._site_init_prompt(None, "Temporary recovery VLAN ID", 3999) == "3999"
        assert policy_cli._site_init_prompt(None, "EX-only prestage/default VLAN name", "TEMP-ACCESS") == "TEMP-ACCESS"
    finally:
        policy_cli._ORIGINAL_SITE_PROMPT = original

    assert captured == [
        (None, "Environment (lab/production)", "production"),
        (None, "Temporary Management VLAN name", "Temp-Management"),
        (None, "Temporary Management VLAN ID", 3999),
        (None, "EX-only prestage/default VLAN name", "TEMP-ACCESS"),
    ]


def test_site_prep_runs_init_discover_stage_with_one_credential_set(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _settings(tmp_path)
    calls = []

    monkeypatch.setattr(policy_cli, "_site_init", lambda args: calls.append(("init", list(args))) or 0)
    monkeypatch.setattr("builtins.input", lambda _prompt: "admin")
    monkeypatch.setattr(policy_cli.getpass, "getpass", lambda _prompt: "secret")
    monkeypatch.setattr(
        policy_cli.site_cli,
        "main",
        lambda argv: calls.append((argv[0], list(argv[1:]))) or 0,
    )

    assert policy_cli._site_prep(["--environment", "lab"]) == 0
    assert calls[0] == ("init", ["--environment", "lab"])
    assert calls[1][0] == "site-discover"
    assert calls[2][0] == "site-stage"
    for _phase, args in calls[1:]:
        assert "--username" in args
        assert args[args.index("--username") + 1] == "admin"
        assert "--password-env" in args
        assert args[args.index("--password-env") + 1] == "EX_MIGRATION_SITE_PASSWORD"
    assert "EX_MIGRATION_SITE_PASSWORD" not in policy_cli.os.environ
