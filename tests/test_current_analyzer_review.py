from __future__ import annotations

import builtins

from ex_migration_analyzer.core import atomic_json
from ex_migration_analyzer.current_cli import review_findings


def _analysis(findings, ports):
    return {
        "analysis_id": "analysis-1",
        "template_variables": {"migration_id": "dh4301"},
        "inputs": {"evidence_set_digest": "evidence-digest"},
        "historical_evidence": {"catalog_digest": "history-digest"},
        "findings": findings,
        "ports": ports,
    }


def _finding(subject, code, message="review"):
    return {
        "severity": "REVIEW",
        "code": code,
        "subject": subject,
        "message": message,
        "evidence": [],
    }


def test_historical_configured_no_mac_is_auto_accepted(tmp_path, monkeypatch):
    analysis = _analysis(
        [
            _finding("ge-0/0/3", "CONFIGURED_NO_MAC"),
            _finding("snapshot", "VIRTUAL_CHASSIS_UNSUPPORTED"),
        ],
        [
            {
                "interface": "ge-0/0/3",
                "observation_history": "HISTORICALLY_OBSERVED",
            }
        ],
    )
    destination = tmp_path / "analysis"
    destination.mkdir()
    atomic_json(destination / "analysis.json", analysis)

    answers = iter([""])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(answers))
    review, action = review_findings(
        destination,
        analysis,
        {"policy_id": "lab", "production_eligible": False},
        "policy-digest",
        True,
    )

    assert action == "CREATED"
    decisions = {item["subject"]: item for item in review["decisions"]}
    assert decisions["ge-0/0/3"]["disposition"] == "ACCEPT_HISTORICAL_EVIDENCE"
    assert decisions["ge-0/0/3"]["note"] is None
    assert decisions["snapshot"]["disposition"] == "ACKNOWLEDGED_LAB_LIMITATION"
    assert review["result"] == "ACCEPTED"


def test_never_observed_silent_ports_use_one_grouped_decision_and_note(tmp_path, monkeypatch):
    analysis = _analysis(
        [
            _finding("ge-0/0/3", "CONFIGURED_NO_MAC"),
            _finding("ge-0/0/4", "CONFIGURED_NO_MAC"),
            _finding("ge-0/0/7", "CONFIGURED_NO_MAC"),
        ],
        [
            {"interface": "ge-0/0/3", "observation_history": "NEVER_OBSERVED"},
            {"interface": "ge-0/0/4", "observation_history": "NEVER_OBSERVED"},
            {"interface": "ge-0/0/7", "observation_history": "NEVER_OBSERVED"},
        ],
    )
    destination = tmp_path / "analysis"
    destination.mkdir()
    atomic_json(destination / "analysis.json", analysis)

    prompts = []
    answers = iter(["1", "collect another discovery window"])

    def fake_input(prompt=""):
        prompts.append(prompt)
        return next(answers)

    monkeypatch.setattr(builtins, "input", fake_input)
    review, action = review_findings(
        destination,
        analysis,
        {"policy_id": "lab", "production_eligible": False},
        "policy-digest",
        True,
    )

    assert action == "CREATED"
    assert sum("Disposition for all listed silent ports" in prompt for prompt in prompts) == 1
    assert sum("Note for this silent-port group" in prompt for prompt in prompts) == 1
    assert len(review["decisions"]) == 3
    assert {item["disposition"] for item in review["decisions"]} == {"REQUIRES_INVESTIGATION"}
    assert {item["note"] for item in review["decisions"]} == {"collect another discovery window"}
    assert review["result"] == "ACTION_REQUIRED"
