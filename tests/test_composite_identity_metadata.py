from copy import deepcopy

from ex_migration_analyzer.composite import build_composite_evidence


def _snapshot(snapshot_id, completed_at):
    return {
        "schema_version": "1.4",
        "snapshot_id": snapshot_id,
        "migration_id": "sw1203",
        "device_role": "old-switch",
        "started_at": completed_at,
        "completed_at": completed_at,
        "lifecycle": "COLLECTED",
        "device": {
            "hostname": "home1-ex4300-vc-fd-sw1203",
            "configured_hostname": "home1-ex4300-vc-fd-sw1203",
            "model": "EX4300",
            "serial_numbers": ["ABC123"],
            "junos_version": "21.4R3",
            "proposed_hostname": "home1-ex4400-vc-fd-sw1203",
            "identity_rule": "old-rule",
        },
        "management": {
            "consistency": "CONSISTENT",
            "vlan_name": "v163",
            "vlan_id": 163,
            "l3_interface": "irb.163",
            "addresses": ["10.100.163.30/24"],
            "production_ipv4": "10.100.163.30",
            "default_gateway": "10.100.163.1",
            "fxp0_addresses": [],
            "mgmt_junos_default_gateways": [],
            "snmp": {},
        },
        "interfaces": [],
        "vlans": [],
        "voice_policy": {},
        "mac_observations": [],
        "collection_policy": {"samples": 1, "duration_seconds": 0},
        "capabilities": {},
        "virtual_chassis": {"status": "collected"},
        "sample_runs": [],
        "lldp_neighbors": [],
        "raw_artifacts": [],
        "warnings": [],
        "errors": [],
    }


def _candidate(snapshot):
    return {
        "snapshot": snapshot,
        "envelope": {"collection_digest": snapshot["snapshot_id"] * 8},
        "blockers": [],
    }


def _build(first, second):
    return build_composite_evidence(
        [_candidate(first), _candidate(second)],
        {"policy_id": "production"},
        "p" * 64,
    )


def test_derived_target_metadata_does_not_create_device_identity_conflict():
    first = _snapshot("11111111", "2026-09-08T20:00:00Z")
    second = deepcopy(first)
    second["snapshot_id"] = "22222222"
    second["completed_at"] = "2026-09-09T01:00:00Z"
    second["device"]["proposed_hostname"] = "different-derived-target"
    second["device"]["identity_rule"] = "new-rule-version"

    composite = _build(first, second)

    assert composite["evidence"]["configuration_consistency"]["device_identity"] == "CONSISTENT"
    assert not any(item["code"] == "DEVICE_IDENTITY_CHANGED" for item in composite["findings"])


def test_top_level_serial_change_is_informational_not_review_or_blocker():
    first = _snapshot("11111111", "2026-09-08T20:00:00Z")
    second = deepcopy(first)
    second["snapshot_id"] = "22222222"
    second["completed_at"] = "2026-09-09T01:00:00Z"
    second["device"]["serial_numbers"] = ["DEF456"]

    composite = _build(first, second)

    consistency = composite["evidence"]["configuration_consistency"]
    assert consistency["device_identity"] == "CONSISTENT"
    assert consistency["device_serial_observation"] == "CHANGED"
    assert len(composite["evidence"]["hardware_observations"]["serial_variants"]) == 2
    assert not any(item["code"] == "DEVICE_IDENTITY_CHANGED" for item in composite["findings"])
    assert not any(item["code"] == "DEVICE_SERIAL_OBSERVATION_CHANGED" for item in composite["findings"])


def test_observed_fact_hostname_change_does_not_override_configured_identity():
    first = _snapshot("11111111", "2026-09-08T20:00:00Z")
    second = deepcopy(first)
    second["snapshot_id"] = "22222222"
    second["completed_at"] = "2026-09-09T01:00:00Z"
    second["device"]["hostname"] = "different-observed-fact"

    composite = _build(first, second)

    assert composite["evidence"]["configuration_consistency"]["device_identity"] == "CONSISTENT"
    assert not any(item["code"] == "DEVICE_IDENTITY_CHANGED" for item in composite["findings"])


def test_configured_hostname_change_remains_blocker():
    first = _snapshot("11111111", "2026-09-08T20:00:00Z")
    second = deepcopy(first)
    second["snapshot_id"] = "22222222"
    second["completed_at"] = "2026-09-09T01:00:00Z"
    second["device"]["configured_hostname"] = "different-switch"

    composite = _build(first, second)

    assert composite["evidence"]["configuration_consistency"]["device_identity"] == "CONFLICT"
    assert any(
        item["code"] == "DEVICE_IDENTITY_CHANGED" and item["severity"] == "BLOCKER"
        for item in composite["findings"]
    )


def test_model_change_is_review_not_identity_change():
    first = _snapshot("11111111", "2026-09-08T20:00:00Z")
    second = deepcopy(first)
    second["snapshot_id"] = "22222222"
    second["completed_at"] = "2026-09-09T01:00:00Z"
    second["device"]["model"] = "EX4400"

    composite = _build(first, second)

    consistency = composite["evidence"]["configuration_consistency"]
    assert consistency["device_identity"] == "CONSISTENT"
    assert consistency["device_model"] == "CHANGED"
    assert any(
        item["code"] == "DEVICE_MODEL_CHANGED" and item["severity"] == "REVIEW"
        for item in composite["findings"]
    )
