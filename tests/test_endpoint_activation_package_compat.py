import hashlib
import json

from ex_migration_provisioner.prestage import choose_package_compat


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def test_current_package_without_retired_recovery_fields_loads_for_endpoint_activation(tmp_path):
    migration_root = tmp_path / "migrations" / "dh4301"
    package_dir = migration_root / "packages" / "0123456789abcdef"
    package_path = package_dir / "package.json"
    package = {
        "schema_version": "1.1",
        "package_id": "0123456789abcdef",
        "migration_id": "dh4301",
        "created_at": "2026-09-14T16:00:00Z",
        "variables": {
            "management_vlan_id": 163,
            "voice_vlan_id": 1111,
            "prestage_access_vlan_id": 3998,
            "uplink_interfaces": ["ge-0/0/0", "ge-0/0/1"],
        },
    }
    _write_json(package_path, package)
    digest = hashlib.sha256(package_path.read_bytes()).hexdigest()
    _write_json(package_dir / "integrity.json", {"package.json": digest})

    selected = choose_package_compat(migration_root)
    variables = selected["package"]["variables"]

    assert variables["recovery_interface"] == ""
    assert variables["temporary_recovery_vlan_id"] == 0

    persisted = json.loads(package_path.read_text(encoding="utf-8"))
    assert "recovery_interface" not in persisted["variables"]
    assert "temporary_recovery_vlan_id" not in persisted["variables"]
    assert hashlib.sha256(package_path.read_bytes()).hexdigest() == digest
