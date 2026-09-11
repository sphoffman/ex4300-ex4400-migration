from pathlib import Path

from ex_migration_analyzer.core import atomic_json
from ex_migration_operator import policy_cli


def test_old_switch_recovery_defaults_required_for_existing_profiles(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("config").mkdir()
    atomic_json(Path("config/site.json"), {"site_profile": "config/site-profile.json"})
    atomic_json(Path("config/site-profile.json"), {"schema_version": "1.1"})
    assert policy_cli._old_switch_recovery_required("config/site.json") is True


def test_old_switch_recovery_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("config").mkdir()
    atomic_json(Path("config/site.json"), {"site_profile": "config/site-profile.json"})
    atomic_json(
        Path("config/site-profile.json"),
        {"schema_version": "1.1", "old_switch_recovery_required": False},
    )
    assert policy_cli._old_switch_recovery_required("config/site.json") is False


def test_policy_status_marks_recovery_satisfied_without_transaction(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("config").mkdir()
    atomic_json(Path("config/site.json"), {"site_profile": "config/site-profile.json"})
    atomic_json(
        Path("config/site-profile.json"),
        {"schema_version": "1.1", "old_switch_recovery_required": False},
    )

    monkeypatch.setattr(
        policy_cli,
        "_ORIGINAL_WORKFLOW_STATUS",
        lambda _root: {
            "old_recovery": "COMPLETE"
            if policy_cli.operator_core._successful_old_recovery(None, None)
            else "PENDING",
            "next_action": "cutover",
        },
    )
    policy_cli._POLICY_SETTINGS = "config/site.json"
    state = policy_cli._policy_workflow_status(tmp_path / "snapshots/migrations/test")
    assert state["old_recovery"] == "COMPLETE"
    assert state["old_recovery_not_required"] is True
