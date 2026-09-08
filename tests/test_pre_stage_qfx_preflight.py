import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from ex_migration_provisioner.core import run_qfx_preflight
from ex_migration_provisioner.preflight import scope_pre_stage_qfx_preflight
from test_provisioner import devices_for, policy


ROOT = Path(__file__).resolve().parents[1]


def test_pre_stage_allows_absent_lldp_until_ex_is_configured():
    devices = devices_for(neighbor="")
    raw = run_qfx_preflight(
        policy(), "sw1203", devices, observed_at="2026-09-08T16:00:00Z"
    )
    assert raw["result"] == "FAIL"

    scoped = scope_pre_stage_qfx_preflight(raw)
    assert scoped["schema_version"] == "1.1"
    assert scoped["readiness_scope"] == "EX4400_PRE_STAGE"
    assert scoped["result"] == "PASS"
    assert "qfx-a.lldp_neighbor_present" in scoped["deferred_checks"]
    assert "qfx-b.lldp_neighbor_present" in scoped["deferred_checks"]
    assert "pair.lldp_neighbor_symmetry" in scoped["deferred_checks"]
    assert "device.lldp_neighbor_present" in scoped["revalidation_required"]

    schema = json.loads((ROOT / "schemas/qfx-preflight-1.1.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(scoped)


def test_pre_stage_allows_link_and_lacp_to_be_deferred():
    devices = devices_for(neighbor="")
    for device in devices.values():
        device.up = False
        device.lacp_up = False
    raw = run_qfx_preflight(
        policy(), "sw1203", devices, observed_at="2026-09-08T16:00:00Z"
    )
    scoped = scope_pre_stage_qfx_preflight(raw)
    assert scoped["result"] == "PASS"
    assert "qfx-a.physical_interface_up" in scoped["deferred_checks"]
    assert "qfx-a.lacp_collecting_distributing" in scoped["deferred_checks"]


def test_pre_stage_rejects_contradictory_lldp_evidence():
    devices = devices_for(neighbor="new-switch")
    devices["qfx-b"].neighbor = "wrong-switch"
    raw = run_qfx_preflight(
        policy(), "sw1203", devices, observed_at="2026-09-08T16:00:00Z"
    )
    scoped = scope_pre_stage_qfx_preflight(raw)
    assert scoped["result"] == "FAIL"
    assert "pair.lldp_neighbor_symmetry" not in scoped["deferred_checks"]


def test_pre_stage_still_rejects_static_qfx_policy_mismatch():
    devices = devices_for(neighbor="")
    devices["qfx-b"].system_id = "00:01:02:03:04:99"
    raw = run_qfx_preflight(
        policy(), "sw1203", devices, observed_at="2026-09-08T16:00:00Z"
    )
    scoped = scope_pre_stage_qfx_preflight(raw)
    assert scoped["result"] == "FAIL"
    assert scoped["devices"][1]["checks"]["configured_lacp_system_id_matches"] is False
