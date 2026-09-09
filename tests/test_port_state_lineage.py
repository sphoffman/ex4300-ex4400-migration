import json

from ex_migration_analyzer.core import sha256_file, validate_collection
from ex_migration_provisioner import port_state_cli
from ex_migration_provisioner.port_state import load_approved_port_state_evidence


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def test_port_state_cli_imports():
    parser = port_state_cli._parser()
    args = parser.parse_args(["sw1203"])
    assert args.migration_id == "sw1203"


def test_loads_only_analysis_bound_discovery_collection(tmp_path):
    migration_root = tmp_path / "migrations" / "sw1203"
    collection = migration_root / "old-switch" / "collections" / "c1"
    raw = collection / "raw" / "terse.txt"
    raw.parent.mkdir(parents=True)
    raw.write_text("ge-0/0/2 up down\n", encoding="utf-8")

    snapshot = {
        "schema_version": "1.4",
        "snapshot_id": "snap1",
        "migration_id": "sw1203",
        "device_role": "old-switch",
        "started_at": "2026-09-09T10:00:00Z",
        "completed_at": "2026-09-09T10:00:01Z",
        "device": {},
        "management": {},
        "collection_policy": {},
        "capabilities": {},
        "interfaces": [{
            "name": "ge-0/0/2",
            "physical_name": "ge-0/0/2",
            "effective_mode": "access",
            "ae_parent": None,
        }],
        "vlans": [],
        "voice_policy": {},
        "mac_observations": [],
        "lldp_neighbors": [],
        "raw_artifacts": [{
            "path": "raw/terse.txt",
            "sha256": sha256_file(raw),
            "command": "show interfaces terse",
            "format": "text",
            "usable": True,
        }],
        "warnings": [],
        "errors": [],
        "sample_runs": [{
            "sample_index": 0,
            "observed_at": "2026-09-09T10:00:00Z",
            "commands": [{
                "command": "show interfaces terse",
                "status": "SUCCESS",
                "text_artifact": "raw/terse.txt",
            }],
        }],
    }
    snapshot_path = collection / "snapshot.json"
    errors_path = collection / "errors.json"
    _write_json(snapshot_path, snapshot)
    _write_json(errors_path, [])
    _write_json(collection / "integrity.json", {
        "snapshot.json": sha256_file(snapshot_path),
        "errors.json": sha256_file(errors_path),
    })
    _snapshot, envelope = validate_collection(collection)

    analysis_id = "a" * 16
    analysis = {
        "analysis_id": analysis_id,
        "composite_evidence": {
            "evidence_set_id": "e" * 16,
            "evidence_set_digest": "f" * 64,
            "collections": [{
                "snapshot_id": "snap1",
                "collection_digest": envelope["collection_digest"],
            }],
        },
    }
    analysis_path = migration_root / "analyses" / analysis_id / "analysis.json"
    _write_json(analysis_path, analysis)
    plan = {
        "plan_id": "plan1",
        "inputs": {
            "analysis_id": analysis_id,
            "analysis_digest": sha256_file(analysis_path),
        },
    }

    evidence = load_approved_port_state_evidence(
        migration_root,
        plan,
        "b" * 64,
    )
    assert evidence["collections"] == [{
        "snapshot_id": "snap1",
        "collection_digest": envelope["collection_digest"],
    }]
    assert evidence["ports"][0]["interface"] == "ge-0/0/2"
    assert evidence["ports"][0]["latest_state"] == "LINK_DOWN"
    assert evidence["lineage"]["analysis_id"] == analysis_id
