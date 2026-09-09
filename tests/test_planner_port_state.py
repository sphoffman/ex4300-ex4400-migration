from ex_migration_planner.core import build_plan, render_plan_report


def test_plan_carries_pre_migration_port_state_as_diagnostic_evidence():
    state = {
        "interface": "ge-0/0/10",
        "samples": 12,
        "counts": {
            "ACTIVE_MAC": 0,
            "UP_SILENT": 0,
            "LINK_DOWN": 12,
            "ADMIN_DOWN": 0,
            "NOT_OBSERVED": 0,
        },
        "stable_state": "LINK_DOWN",
        "latest_state": "LINK_DOWN",
        "latest_admin_status": "up",
        "latest_oper_status": "down",
        "first_observed_at": "2026-09-06T12:00:00Z",
        "latest_observed_at": "2026-09-09T12:00:00Z",
    }
    analysis = {
        "analysis_id": "a" * 16,
        "result": "READY",
        "findings": [],
        "inputs": {
            "snapshot_id": "b" * 16,
            "collection_digest": "c" * 64,
            "approval_digest": "d" * 64,
            "policy_digest": "e" * 64,
            "policy_production_eligible": False,
        },
        "template_variables": {
            "migration_id": "sw1203",
            "management_vlan_id": 163,
            "configured_vlans": [],
        },
        "composite_evidence": {
            "port_state_summary": {
                "schema_version": "1.0",
                "ports": [state],
            }
        },
        "ports": [
            {
                "interface": "ge-0/0/10",
                "description": "Unused desk",
                "configured_data_vlan_id": None,
                "observed_data_vlan_ids": [],
                "unique_macs": [],
                "historical_observations": [],
                "disposition": "UNUSED_ACCESS_PORT",
            }
        ],
    }

    plan = build_plan(
        analysis,
        "f" * 64,
        review=None,
        review_digest=None,
        planner_version="0.7.3",
    )

    intent = plan["port_intents"][0]
    assert intent["old_interface"] == "ge-0/0/10"
    assert intent["pre_migration_state"] == state
    assert intent["planned_action"] == "LEAVE_TEMPLATE_DEFAULT"
    assert "COMPARE_PRE_POST_PORT_STATE" in plan["phase_intents"]["post_move"]["include"]
    report = render_plan_report(plan)
    assert "LINK_DOWN" in report
    assert "diagnostic evidence" in report
