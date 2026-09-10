import json

from ex_migration_analyzer.core import sha256_file
from ex_migration_operator import current_cli
from ex_migration_operator.endpoint_exceptions import active_endpoint_exceptions


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_active_exception_retires_when_endpoint_is_later_completed(tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    directory = root / "operator" / "endpoint-exceptions" / "e1"
    path = directory / "exception.json"
    _write_json(path, {
        "schema_version": "1.0",
        "migration_id": "sw1203",
        "approved_plan_digest": "a" * 64,
        "accepted": True,
        "unresolved": [
            {"old_interface": "ge-0/0/4", "reason": "NO_APPROVED_MAC_OBSERVED_POST_MOVE"}
        ],
    })
    _write_json(directory / "integrity.json", {"exception.json": sha256_file(path)})

    active = active_endpoint_exceptions(root, "a" * 64, completed_old_interfaces=[])
    assert sorted(active) == ["ge-0/0/4"]

    active = active_endpoint_exceptions(
        root,
        "a" * 64,
        completed_old_interfaces=["ge-0/0/4"],
    )
    assert active == {}


def test_exception_satisfied_progress_advances_to_validate(monkeypatch, tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    legacy_state = {
        "migration_id": "sw1203",
        "collections": 2,
        "analysis": "COMPLETE",
        "plan": "APPROVED",
        "package": "COMPLETE",
        "render": "COMPLETE",
        "identity": "COMPLETE",
        "ex4400_prestage": "COMPLETE",
        "old_recovery": "COMPLETE",
        "silent_probe": {"status": "NOT_REQUIRED", "candidate_count": 0},
        "physical_cutover": "INFERRED_COMPLETE",
        "qfx_attachment": "COMPLETE",
        "qfx_stage": "COMPLETE",
        "endpoints": "7/8",
        "port_state": "PENDING",
        "cabling_report": "PENDING",
        "cleanup": "PENDING",
        "next_action": "activate",
    }
    selected = {"plan": {"plan_id": "p1"}, "plan_digest": "a" * 64}
    progress = {
        "required_count": 8,
        "completed_count": 7,
        "accepted_count": 1,
        "satisfied": True,
    }
    monkeypatch.setattr(current_cli.legacy, "workflow_status", lambda _root: dict(legacy_state))
    monkeypatch.setattr(current_cli.provisioner_base, "choose_approved_plan", lambda _root: selected)
    monkeypatch.setattr(current_cli, "endpoint_progress", lambda _root, _selected: progress)
    monkeypatch.setattr(current_cli.operator_core, "_valid_jsons", lambda _root, _pattern: [])

    value = current_cli.workflow_status(root)
    assert value["endpoints"] == "7/8 + 1 ACCEPTED_EXCEPTION"
    assert value["next_action"] == "validate"


def test_explicit_activate_remains_callable_for_late_reconciliation(monkeypatch, tmp_path):
    root = tmp_path / "migrations" / "sw1203"
    called = []
    monkeypatch.setattr(current_cli.legacy, "_activate", lambda migration_id, extra: called.append((migration_id, extra)) or 0)
    monkeypatch.setattr(current_cli.legacy, "_settings", lambda _path: {"snapshot_root": str(tmp_path / "migrations")})
    monkeypatch.setattr(current_cli, "_offer_exception_acceptance", lambda _root: 0)

    assert current_cli._activate("sw1203", []) == 0
    assert called == [("sw1203", [])]
