from pathlib import Path

from ex_migration_operator import cli


def _state(identity="PENDING", ex4400="PENDING", old="PENDING"):
    return {
        "package": "COMPLETE",
        "render": "COMPLETE",
        "identity": identity,
        "ex4400_prestage": ex4400,
        "old_recovery": old,
    }


def test_prestage_reuses_one_credential_prompt_across_live_steps(monkeypatch, tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    monkeypatch.setattr(cli, "_settings", lambda _path: {"snapshot_root": str(tmp_path)})
    monkeypatch.setattr(cli, "migration_root", lambda _settings, _migration_id: root)
    monkeypatch.setattr(cli, "_site_environment", lambda _settings: "lab")
    monkeypatch.setattr(cli, "source_address_from_evidence", lambda _root: "10.255.3.18")

    calls = {"status": 0, "input": 0, "password": 0}

    def status(_root):
        calls["status"] += 1
        # Before identify: all three live steps pending. After each child command,
        # expose the artifact that command would have created.
        if calls["status"] <= 4:
            return _state()
        if calls["status"] == 5:
            return _state(identity="COMPLETE")
        return _state(identity="COMPLETE", ex4400="COMPLETE")

    monkeypatch.setattr(cli, "workflow_status", status)

    def fake_input(prompt):
        calls["input"] += 1
        assert prompt == "Migration device username: "
        return "admin"

    def fake_getpass(prompt):
        calls["password"] += 1
        assert prompt == "Migration device password: "
        return "secret"

    monkeypatch.setattr("builtins.input", fake_input)
    monkeypatch.setattr(cli.getpass, "getpass", fake_getpass)

    commands = []
    monkeypatch.setattr(cli, "_run_module", lambda module, args: commands.append((module, list(args))) or 0)

    assert cli._prestage("sw1203", ["--oob-address", "10.255.3.18/24"]) == 0
    assert calls["input"] == 1
    assert calls["password"] == 1
    assert [args[0] for _module, args in commands] == [
        "identify",
        "run",
        "stage-old-recovery",
    ]

    for _module, args in commands:
        assert ["--username", "admin"] == args[args.index("--username"):args.index("--username") + 2]
        env_index = args.index("--password-env")
        assert args[env_index + 1] == "EX_MIGRATION_PRESTAGE_PASSWORD"

    recovery_args = commands[-1][1]
    transport_index = recovery_args.index("--transport-address")
    assert recovery_args[transport_index + 1] == "10.255.3.18"
    assert "EX_MIGRATION_PRESTAGE_PASSWORD" not in cli.os.environ


def test_prestage_does_not_infer_transport_override_in_production(monkeypatch, tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    monkeypatch.setattr(cli, "_settings", lambda _path: {"snapshot_root": str(tmp_path)})
    monkeypatch.setattr(cli, "migration_root", lambda _settings, _migration_id: root)
    monkeypatch.setattr(cli, "_site_environment", lambda _settings: "production")
    monkeypatch.setattr(
        cli,
        "source_address_from_evidence",
        lambda _root: (_ for _ in ()).throw(AssertionError("production must not use discovery transport")),
    )
    monkeypatch.setenv("TEST_MIGRATION_PASSWORD", "secret")
    monkeypatch.setattr(
        cli,
        "workflow_status",
        lambda _root: _state(identity="COMPLETE", ex4400="COMPLETE", old="PENDING"),
    )

    commands = []
    monkeypatch.setattr(cli, "_run_module", lambda module, args: commands.append((module, list(args))) or 0)

    assert cli._prestage(
        "sw1203",
        ["--username", "admin", "--password-env", "TEST_MIGRATION_PASSWORD"],
    ) == 0
    assert len(commands) == 1
    recovery_args = commands[0][1]
    assert recovery_args[0] == "stage-old-recovery"
    assert "--transport-address" not in recovery_args
