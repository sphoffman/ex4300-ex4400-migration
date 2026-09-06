import hashlib
import json
from pathlib import Path

import pytest

from ex_migration_analyzer.core import AnalysisError, analyze, canonical_bytes, correlate, validate_collection
from ex_migration_analyzer.cli import candidate_rank, inspect_candidates, load_settings, prepare_history, review_findings


def write_collection(tmp_path, migration_id="dh4301", vlan_id=100, extra_vlan=None):
    collection = tmp_path / "snapshots" / "migrations" / migration_id / "old-switch" / "collections" / "collection-1"
    raw = collection / "raw" / "observations" / "0000"
    raw.mkdir(parents=True)
    artifact = raw / "mac.txt"
    artifact.write_text("safe operational evidence\n")
    artifact_hash = hashlib.sha256(artifact.read_bytes()).hexdigest()
    vlans = [
        {"name": "v%d" % vlan_id, "vlan_id": vlan_id, "observed_mac_count": 1},
        {"name": "v163", "vlan_id": 163, "observed_mac_count": 0},
        {"name": "voip", "vlan_id": 1111, "observed_mac_count": 1},
    ]
    if extra_vlan:
        vlans.append({"name": extra_vlan[0], "vlan_id": extra_vlan[1], "observed_mac_count": 0})
    snapshot = {
        "schema_version": "1.3", "snapshot_id": "abc123", "migration_id": migration_id,
        "device_role": "old-switch", "started_at": "2026-09-05T00:00:00Z", "completed_at": "2026-09-05T00:30:00Z",
        "device": {"hostname": "home1-ex4300-vc-fd-%s" % migration_id, "proposed_hostname": "home1-ex4400-vc-fd-%s" % migration_id},
        "management": {"consistency": "CONSISTENT", "vlan_id": 163, "vlan_name": "v163", "l3_interface": "irb.163", "addresses": ["10.100.163.10/24"], "production_ipv4": "10.100.163.10", "default_gateway": "10.100.163.1", "snmp": {"location": "lab", "engine_id": "10.100.163.10"}},
        "collection_policy": {"samples": 31, "duration_seconds": 1800},
        "sample_runs": [
            {"sample_index": index, "observed_at": "2026-09-05T00:%02d:00Z" % min(index, 30), "commands": [
                {"command": command, "status": "SUCCESS"} for command in (
                    "show ethernet-switching table detail", "show interfaces terse",
                    "show lldp neighbors detail", "show lacp interfaces",
                )
            ]} for index in range(31)
        ],
        "capabilities": {
            "show ethernet-switching table detail": "xml_and_text", "show interfaces terse": "xml_and_text",
            "show lldp neighbors detail": "xml_and_text", "show lacp interfaces": "xml_and_text",
        },
        "virtual_chassis": {"status": "collected"},
        "interfaces": [
            {"physical_name": "ge-0/0/2", "effective_mode": "access", "ae_parent": None, "description": "Desk", "untagged_vlan": {"name": "v%d" % vlan_id, "vlan_id": vlan_id}},
            {"physical_name": "ge-0/0/3", "effective_mode": "access", "ae_parent": None, "description": "Silent", "untagged_vlan": {"name": "v%d" % vlan_id, "vlan_id": vlan_id}},
            {"physical_name": "ge-0/0/0", "effective_mode": None, "ae_parent": "ae0", "description": None, "untagged_vlan": None},
        ],
        "vlans": vlans, "voice_policy": {"valid": True, "vlan_id": 1111},
        "mac_observations": [
            {"mac": "02:00:00:00:00:01", "physical_interface": "ge-0/0/2", "interface_class": "physical_access", "vlan": {"name": "v%d" % vlan_id, "vlan_id": vlan_id}},
            {"mac": "02:00:00:00:00:02", "physical_interface": "ge-0/0/2", "interface_class": "physical_access", "vlan": {"name": "voip", "vlan_id": 1111}},
            {"mac": "02:00:00:00:00:ff", "physical_interface": "ge-0/0/0", "interface_class": "ae_member", "vlan": {"name": "v%d" % vlan_id, "vlan_id": vlan_id}},
        ],
        "lldp_neighbors": [],
        "raw_artifacts": [{"path": "raw/observations/0000/mac.txt", "sha256": artifact_hash}],
        "warnings": [], "errors": [],
    }
    (collection / "snapshot.json").write_text(json.dumps(snapshot, indent=2) + "\n")
    (collection / "errors.json").write_text("[]\n")
    (collection / "report.md").write_text("fixture\n")
    integrity = {}
    for name in ("snapshot.json", "errors.json", "report.md"):
        integrity[name] = hashlib.sha256((collection / name).read_bytes()).hexdigest()
    (collection / "integrity.json").write_text(json.dumps(integrity, indent=2) + "\n")
    return collection, snapshot


@pytest.mark.parametrize("migration_id,vlan_id,extra_vlan", [
    ("dh4301", 100, None), ("nh5302", 200, None), ("sw1203", 100, ("UNUSED-TEST", 300)),
])
def test_three_lab_profiles(tmp_path, migration_id, vlan_id, extra_vlan):
    collection, _ = write_collection(tmp_path, migration_id, vlan_id, extra_vlan)
    snapshot, envelope = validate_collection(collection)
    ports, excluded, findings = correlate(snapshot, {})
    assert ports[0]["disposition"] == "PHONE_PLUS_PC"
    assert ports[1]["disposition"] == "CONFIGURED_NO_MAC"
    assert len(excluded) == 1
    if migration_id == "sw1203":
        assert next(v for v in snapshot["vlans"] if v["name"] == "UNUSED-TEST")["observed_mac_count"] == 0


def test_corrupt_raw_artifact_is_refused(tmp_path):
    collection, _ = write_collection(tmp_path)
    next((collection / "raw").rglob("*.txt")).write_text("tampered\n")
    with pytest.raises(AnalysisError, match="integrity failure"):
        validate_collection(collection)


def test_same_mac_multiple_vlans_same_port_uses_static_vlan(tmp_path):
    collection, snapshot = write_collection(tmp_path)
    duplicate = dict(snapshot["mac_observations"][0])
    duplicate["vlan"] = {"name": "v200", "vlan_id": 200}
    snapshot["mac_observations"].append(duplicate)
    ports, _, findings = correlate(snapshot, {})
    assert ports[0]["configured_data_vlan_id"] == 100
    assert ports[0]["disposition"] == "PHONE_PLUS_PC"
    assert not any(item["code"] == "DATA_VLAN_UNRESOLVED" for item in findings)


def test_no_phone_is_normal(tmp_path):
    _, snapshot = write_collection(tmp_path)
    snapshot["mac_observations"] = snapshot["mac_observations"][:1]
    ports, _, findings = correlate(snapshot, {})
    assert ports[0]["disposition"] == "DATA_ONLY"
    assert not any("PHONE" in item["code"] for item in findings)


def test_access_port_without_vlan_or_mac_is_distinct(tmp_path):
    _, snapshot = write_collection(tmp_path)
    snapshot["interfaces"][1]["untagged_vlan"] = None
    snapshot["interfaces"][1]["oper_status"] = "down"
    ports, _, findings = correlate(snapshot, {})
    assert ports[1]["disposition"] == "UNUSED_ACCESS_PORT"
    assert not any(item["subject"] == "ge-0/0/3" for item in findings)


def test_operational_unassigned_port_requires_review(tmp_path):
    _, snapshot = write_collection(tmp_path)
    snapshot["interfaces"][1]["untagged_vlan"] = None
    snapshot["interfaces"][1]["oper_status"] = "up"
    ports, _, findings = correlate(snapshot, {})
    assert ports[1]["disposition"] == "ACTIVE_UNASSIGNED_SILENT"
    assert any(item["code"] == "ACTIVE_UNASSIGNED_SILENT" for item in findings)


def test_analysis_id_is_deterministic(tmp_path):
    collection, _ = write_collection(tmp_path)
    snapshot, envelope = validate_collection(collection)
    policy = {"accepted_snapshot_schemas": ["1.3"], "observation": {"minimum_samples": 1}, "required_capabilities": [], "require_virtual_chassis": False}
    first = analyze(snapshot, envelope, policy, "p", "a", "0.3.0")
    second = analyze(snapshot, envelope, policy, "p", "a", "0.3.0")
    assert first == second


def test_local_site_policy_overrides_tracked_default(tmp_path):
    config = tmp_path / "config"
    config.mkdir()
    (config / "site.json").write_text('{"analysis_policy":"policies/production-old-v1.json"}')
    (config / "site.local.json").write_text('{"analysis_policy":"policies/lab-smoke-v1.json"}')
    assert load_settings(config / "site.json")["analysis_policy"] == "policies/lab-smoke-v1.json"


def test_history_uses_all_eligible_snapshots(tmp_path):
    candidates = []
    for migration_id, mac in (("one", "02:00:00:00:00:01"), ("two", "02:00:00:00:00:03")):
        collection, snapshot = write_collection(tmp_path / migration_id)
        snapshot["snapshot_id"] = migration_id
        snapshot["mac_observations"][0]["mac"] = mac
        snapshot["mac_observations"] = snapshot["mac_observations"][:1]
        preview = {"ports": [{"interface": "ge-0/0/2", "unique_macs": [mac]}]}
        candidates.append({"snapshot": snapshot, "preview": preview, "blockers": [], "envelope": {"collection_digest": ("a" if migration_id == "one" else "b") * 64}})
    history = prepare_history(candidates)
    assert len(history["catalog"]) == 2
    assert candidates[0]["historical_coverage"] == 1
    assert len(candidates[0]["historically_missing"]) == 1


def test_lab_limitation_review_is_digest_bound(tmp_path, monkeypatch):
    destination = tmp_path / "analysis"
    destination.mkdir()
    analysis = {
        "analysis_id": "1" * 16,
        "template_variables": {"migration_id": "dh4301"},
        "historical_evidence": {"catalog_digest": "2" * 64},
        "ports": [],
        "findings": [{"severity": "REVIEW", "code": "VIRTUAL_CHASSIS_UNSUPPORTED", "subject": "snapshot", "message": "unsupported", "evidence": []}],
    }
    (destination / "analysis.json").write_text(json.dumps(analysis))
    monkeypatch.setattr("builtins.input", lambda _prompt: "")
    review, action = review_findings(destination, analysis, {"policy_id": "lab", "production_eligible": False}, "3" * 64, True)
    assert action == "CREATED"
    assert review["result"] == "ACCEPTED"
    assert review["production_eligible"] is False
    assert review["decisions"][0]["disposition"] == "ACKNOWLEDGED_LAB_LIMITATION"
    assert (destination / "reviews" / review["review_id"] / "integrity.json").is_file()
