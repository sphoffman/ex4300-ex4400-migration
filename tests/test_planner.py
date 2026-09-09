import pytest

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes
from ex_migration_planner.core import PlanError, build_plan
from ex_migration_planner.cli import approve_plan, write_plan


def sample_analysis():
    return {
        "schema_version": "1.0", "analysis_id": "a" * 16, "result": "REVIEW_REQUIRED",
        "inputs": {"snapshot_id": "snapshot-1", "collection_digest": "1" * 64, "approval_digest": "2" * 64, "policy_digest": "3" * 64},
        "template_variables": {
            "migration_id": "sw1203", "old_hostname": "home1-ex4300-vc-fd-sw1203", "new_hostname": "home1-ex4400-vc-fd-sw1203",
            "management_vlan_id": 163, "management_vlan_name": "v163", "management_interface": "irb.163",
            "management_ip": "10.100.163.30", "management_prefix": "10.100.163.30/24", "management_gateway": "10.100.163.1",
            "snmp_location": "<home><1><sw1203>", "snmp_engine_id": "10.100.163.30",
            "configured_vlans": [
                {"name": "v100", "vlan_id": 100, "observed": True, "observed_mac_count": 2, "irb_interface": None},
                {"name": "v163", "vlan_id": 163, "observed": False, "observed_mac_count": 0, "irb_interface": "irb.163"},
                {"name": "UNUSED-TEST", "vlan_id": 300, "observed": False, "observed_mac_count": 0, "irb_interface": None},
            ],
        },
        "ports": [
            {"interface": "ge-0/0/2", "description": "Desk", "configured_data_vlan_id": 100, "observed_data_vlan_ids": [100], "unique_macs": ["02:00:00:00:00:01"], "historical_observations": [], "disposition": "DATA_ONLY"},
            {"interface": "ge-0/0/10", "description": None, "configured_data_vlan_id": None, "observed_data_vlan_ids": [], "unique_macs": [], "historical_observations": [], "disposition": "UNUSED_ACCESS_PORT"},
        ],
        "findings": [{"severity": "REVIEW", "code": "VIRTUAL_CHASSIS_UNSUPPORTED", "subject": "snapshot", "message": "unsupported", "evidence": []}],
    }


def sample_review(analysis_digest, result="ACCEPTED"):
    return {"analysis_digest": analysis_digest, "analysis_id": "a" * 16, "result": result, "production_eligible": False, "decisions": []}


def test_plan_is_deterministic_and_preserves_unobserved_vlan():
    analysis = sample_analysis(); digest = sha256_bytes(canonical_bytes(analysis)); review = sample_review(digest)
    first = build_plan(analysis, digest, review, "4" * 64, "0.6.0")
    second = build_plan(analysis, digest, review, "4" * 64, "0.6.0")
    assert first == second
    assert first["eligibility"]["status"] == "LAB_ONLY"
    assert next(v for v in first["vlan_intents"] if v["name"] == "UNUSED-TEST")["observed"] is False
    assert first["qfx_intent"]["required_non_management_vlan_ids"] == [100, 300]
    assert first["safety"]["device_writes_allowed"] is False
    assert first["statistics"]["configured_unobserved_vlans"] == 1
    assert first["statistics"]["template_default_ports"] == 1


def test_plan_requires_accepted_digest_bound_review():
    analysis = sample_analysis(); digest = sha256_bytes(canonical_bytes(analysis))
    with pytest.raises(PlanError, match="accepted"):
        build_plan(analysis, digest, sample_review(digest, "ACTION_REQUIRED"), "4" * 64, "0.6.0")
    with pytest.raises(PlanError, match="not bound"):
        build_plan(analysis, digest, sample_review("9" * 64), "4" * 64, "0.6.0")


def test_blocked_analysis_cannot_be_planned():
    analysis = sample_analysis(); analysis["result"] = "BLOCKED"; digest = sha256_bytes(canonical_bytes(analysis))
    with pytest.raises(PlanError, match="blocked"):
        build_plan(analysis, digest, sample_review(digest), "4" * 64, "0.6.0")


def test_unused_and_endpoint_actions_are_distinct():
    analysis = sample_analysis(); digest = sha256_bytes(canonical_bytes(analysis))
    plan = build_plan(analysis, digest, sample_review(digest), "4" * 64, "0.6.0")
    actions = {item["old_interface"]: item["planned_action"] for item in plan["port_intents"]}
    assert actions["ge-0/0/2"] == "CORRELATE_AFTER_CABLE_MOVE"
    assert actions["ge-0/0/10"] == "LEAVE_TEMPLATE_DEFAULT"


def test_historical_mac_from_other_snapshot_is_promoted_when_port_is_consistent():
    analysis = sample_analysis()
    analysis["ports"][0]["historical_observations"] = [
        {"mac": "02:00:00:00:00:01", "vlan_id": 100, "interface": "ge-0/0/2", "snapshot_ids": ["snapshot-1"]},
        {"mac": "02:00:00:00:00:02", "vlan_id": 100, "interface": "ge-0/0/2", "snapshot_ids": ["snapshot-2"]},
    ]
    digest = sha256_bytes(canonical_bytes(analysis))
    plan = build_plan(analysis, digest, sample_review(digest), "4" * 64, "0.7.1")
    port = next(item for item in plan["port_intents"] if item["old_interface"] == "ge-0/0/2")
    assert port["baseline_endpoint_macs"] == ["02:00:00:00:00:01"]
    assert port["endpoint_macs"] == ["02:00:00:00:00:01", "02:00:00:00:00:02"]
    assert port["historical_endpoint_macs"] == ["02:00:00:00:00:01", "02:00:00:00:00:02"]
    assert port["historical_conflicting_macs"] == []
    assert plan["statistics"]["historical_endpoint_macs_promoted"] == 1


def test_cross_snapshot_mac_movement_is_not_used_as_automatic_endpoint_identity():
    analysis = sample_analysis()
    analysis["ports"][0]["historical_observations"] = [
        {"mac": "02:00:00:00:00:09", "vlan_id": 100, "interface": "ge-0/0/2", "snapshot_ids": ["snapshot-1"]},
    ]
    analysis["ports"].append({
        "interface": "ge-0/0/3", "description": "Other Desk", "configured_data_vlan_id": 100,
        "observed_data_vlan_ids": [], "unique_macs": [],
        "historical_observations": [
            {"mac": "02:00:00:00:00:09", "vlan_id": 100, "interface": "ge-0/0/3", "snapshot_ids": ["snapshot-2"]},
        ],
        "disposition": "CONFIGURED_NO_MAC",
    })
    analysis["findings"].append({
        "severity": "REVIEW", "code": "CONFIGURED_NO_MAC", "subject": "ge-0/0/3", "message": "silent", "evidence": []
    })
    digest = sha256_bytes(canonical_bytes(analysis))
    review = sample_review(digest)
    review["decisions"] = [{
        "code": "CONFIGURED_NO_MAC", "subject": "ge-0/0/3", "disposition": "ACCEPT_HISTORICAL_EVIDENCE"
    }]
    plan = build_plan(analysis, digest, review, "4" * 64, "0.7.1")
    port = next(item for item in plan["port_intents"] if item["old_interface"] == "ge-0/0/3")
    assert port["endpoint_macs"] == []
    assert port["historical_conflicting_macs"] == ["02:00:00:00:00:09"]
    assert port["planned_action"] == "HOLD_FOR_OPERATOR_RESOLUTION"
    assert plan["statistics"]["historical_conflicting_macs"] == 1


def test_standard_plan_approval_uses_one_prompt_and_audit_reason(tmp_path, monkeypatch):
    analysis = sample_analysis(); digest = sha256_bytes(canonical_bytes(analysis))
    plan = build_plan(analysis, digest, sample_review(digest), "4" * 64, "0.6.1")
    destination, _action = write_plan(tmp_path, plan)
    prompts = []

    def answer(prompt):
        prompts.append(prompt)
        return "y"

    monkeypatch.setattr("builtins.input", answer)
    approval, action = approve_plan(destination, plan, True)
    assert action == "CREATED"
    assert len(prompts) == 1
    assert approval["reason"] == "Approved generated migration intent without modification"
