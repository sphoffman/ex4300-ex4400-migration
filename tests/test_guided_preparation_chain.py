from pathlib import Path

from ex_migration_operator import current_cli


def _status(next_action):
    return {
        "migration_id": "dh4301",
        "next_action": next_action,
    }


def test_resume_chains_successful_build_directly_into_prestage(monkeypatch):
    root = Path("/tmp/dh4301")
    statuses = iter([_status("build"), _status("prestage")])
    calls = []

    monkeypatch.setattr(current_cli.legacy, "_settings", lambda _path: {})
    monkeypatch.setattr(current_cli, "migration_root", lambda _settings, _migration_id: root)
    monkeypatch.setattr(current_cli, "workflow_status", lambda _root: next(statuses))
    monkeypatch.setattr(current_cli.legacy, "_status_text", lambda _state: None)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    monkeypatch.setattr(
        current_cli,
        "_dispatch",
        lambda migration_id, command, extra: calls.append((migration_id, command, list(extra))) or 0,
    )

    assert current_cli._resume("dh4301") == 0
    assert calls == [
        ("dh4301", "build", []),
        ("dh4301", "prestage", []),
    ]


def test_resume_does_not_prestage_when_build_fails(monkeypatch):
    root = Path("/tmp/dh4301")
    calls = []

    monkeypatch.setattr(current_cli.legacy, "_settings", lambda _path: {})
    monkeypatch.setattr(current_cli, "migration_root", lambda _settings, _migration_id: root)
    monkeypatch.setattr(current_cli, "workflow_status", lambda _root: _status("build"))
    monkeypatch.setattr(current_cli.legacy, "_status_text", lambda _state: None)
    monkeypatch.setattr("builtins.input", lambda _prompt: "")

    def dispatch(migration_id, command, extra):
        calls.append((migration_id, command, list(extra)))
        return 1

    monkeypatch.setattr(current_cli, "_dispatch", dispatch)

    assert current_cli._resume("dh4301") == 1
    assert calls == [("dh4301", "build", [])]
