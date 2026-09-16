import json

import pytest

from ex_migration_operator import cli, current_cli
from ex_migration_operator.core import OperatorError


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _ready_state():
    return {
        "physical_cutover": "COMPLETE",
        "qfx_attachment": "COMPLETE",
        "qfx_stage": "COMPLETE",
        "endpoints": "PENDING",
    }


def test_operator_activate_forwards_plan_only_and_observation_id(monkeypatch, tmp_path):
    environment = tmp_path / "environment.lab.json"
    _write_json(environment, {"environment": "lab"})

    monkeypatch.setattr(cli, "_settings", lambda _path: {"snapshot_root": str(tmp_path)})
    monkeypatch.setattr(cli, "migration_root", lambda _settings, migration_id: tmp_path / migration_id)
    monkeypatch.setattr(cli, "workflow_status", lambda _root: _ready_state())
    monkeypatch.setattr(
        cli,
        "_prestage_credentials",
        lambda _args: ("admin", "TEST_PASSWORD", None),
    )

    calls = []
    monkeypatch.setattr(
        cli,
        "_run_module",
        lambda module, args: calls.append((module, list(args))) or 0,
    )

    result = cli._activate(
        "dh4301",
        [
            "--environment",
            str(environment),
            "--plan-only",
            "--observation-id",
            "79720a061c216eb9",
        ],
    )

    assert result == 0
    assert len(calls) == 1
    module, args = calls[0]
    assert module == "ex_migration_provisioner.cli"
    assert args[0:2] == ["activate-endpoints", "dh4301"]
    assert "--plan-only" in args
    assert args[args.index("--observation-id") + 1] == "79720a061c216eb9"


def test_operator_activate_rejects_observation_replay_in_production(monkeypatch, tmp_path):
    environment = tmp_path / "environment.production.json"
    _write_json(environment, {"environment": "production"})

    monkeypatch.setattr(cli, "_settings", lambda _path: {"snapshot_root": str(tmp_path)})
    monkeypatch.setattr(cli, "migration_root", lambda _settings, migration_id: tmp_path / migration_id)
    monkeypatch.setattr(cli, "workflow_status", lambda _root: _ready_state())

    with pytest.raises(OperatorError, match="only in a lab environment"):
        cli._activate(
            "dh4301",
            [
                "--environment",
                str(environment),
                "--observation-id",
                "79720a061c216eb9",
            ],
        )


def test_current_activate_plan_only_does_not_offer_endpoint_exceptions(monkeypatch):
    monkeypatch.setattr(current_cli.legacy, "_activate", lambda _migration_id, _extra: 0)

    def _unexpected(_root):
        raise AssertionError("plan-only must not offer endpoint exception acceptance")

    monkeypatch.setattr(current_cli, "_offer_exception_acceptance", _unexpected)

    assert current_cli._activate("dh4301", ["--plan-only"]) == 0
