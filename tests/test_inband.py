import hashlib
import json

import pytest

from ex_migration_analyzer.core import canonical_bytes, sha256_bytes
from ex_migration_provisioner.core import ProvisioningError
from ex_migration_provisioner.inband import (
    build_validation,
    choose_qfx_transaction,
    lab_probe_command,
    parse_ed25519_fingerprint,
    planned_management_ip,
    validate_environment_profile,
)


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _write_integrity_json(path):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    _write_json(path.parent / "integrity.json", {path.name: digest})


def _write_qfx_plan(migration_root, qfx_plan_id, migration_plan_digest):
    directory = migration_root / "qfx-vlan-plans" / qfx_plan_id
    path = directory / "plan.json"
    _write_json(path, {
        "qfx_plan_id": qfx_plan_id,
        "migration_id": "sw1203",
        "inputs": {"migration_plan_digest": migration_plan_digest},
        "result": "PASS",
    })
    _write_integrity_json(path)


def _write_qfx_transaction(migration_root, transaction_id, qfx_plan_id, confirmed_at, status="COMMITTED_AND_CONFIRMED"):
    directory = migration_root / "qfx-transactions" / transaction_id
    path = directory / "transaction.json"
    _write_json(path, {
        "transaction_id": transaction_id,
        "migration_id": "sw1203",
        "qfx_plan_id": qfx_plan_id,
        "status": status,
        "confirmed_at": confirmed_at,
        "validation": {"result": "PASS"},
    })
    _write_integrity_json(path)


def test_lab_environment_profile_is_portable():
    profile = {
        "schema_version": "1.0",
        "environment": "lab",
        "inband_validation": {
            "mode": "lab-probe",
            "target_port": 830,
            "timeout_seconds": 5,
            "probe": {
                "host": "10.255.3.29",
                "port": 22,
                "username": "lab",
                "host_key_verification": "accept-ephemeral-lab-key",
            },
        },
    }
    assert validate_environment_profile(profile) is profile
    moved = json.loads(json.dumps(profile))
    moved["inband_validation"]["probe"]["host"] = "10.255.8.44"
    assert validate_environment_profile(moved) is moved


def test_lab_probe_mode_requires_lab_environment():
    profile = {
        "schema_version": "1.0",
        "environment": "production",
        "inband_validation": {
            "mode": "lab-probe",
            "probe": {
                "host": "10.0.0.1",
                "username": "lab",
                "host_key_verification": "accept-ephemeral-lab-key",
            },
        },
    }
    with pytest.raises(ProvisioningError, match="lab-probe"):
        validate_environment_profile(profile)


def test_parse_ed25519_fingerprint_from_multi_key_scan():
    output = "\n".join([
        "256 SHA256:ecdsa [10.100.163.30]:830 (ECDSA)",
        "2048 SHA256:rsa [10.100.163.30]:830 (RSA)",
        "256 SHA256:CHaUZb5H5Gy6mJeMLv7X6wklT9h99mkpxkzGcYcCrHc [10.100.163.30]:830 (ED25519)",
    ])
    assert parse_ed25519_fingerprint(output) == "SHA256:CHaUZb5H5Gy6mJeMLv7X6wklT9h99mkpxkzGcYcCrHc"


def test_lab_probe_command_checks_tcp_before_fingerprint():
    command = lab_probe_command("10.100.163.30", 830, 5)
    assert "nc -z -w 5 10.100.163.30 830" in command
    assert "ssh-keyscan -T 5 -p 830 10.100.163.30" in command


def test_management_ip_comes_from_approved_plan():
    plan = {"template_variables": {"management_ip": "10.100.163.30"}}
    assert planned_management_ip(plan) == "10.100.163.30"


def test_choose_qfx_transaction_requires_committed_and_validated(tmp_path):
    migration_root = tmp_path / "migrations" / "sw1203"
    tx_dir = migration_root / "qfx-transactions" / "good"
    tx = {
        "transaction_id": "good",
        "migration_id": "sw1203",
        "status": "COMMITTED_AND_CONFIRMED",
        "confirmed_at": "2026-09-08T18:00:00Z",
        "validation": {"result": "PASS"},
    }
    _write_json(tx_dir / "transaction.json", tx)
    _write_integrity_json(tx_dir / "transaction.json")

    bad_dir = migration_root / "qfx-transactions" / "bad"
    bad = dict(tx)
    bad.update({"transaction_id": "bad", "status": "ROLLED_BACK"})
    _write_json(bad_dir / "transaction.json", bad)
    _write_integrity_json(bad_dir / "transaction.json")

    selected = choose_qfx_transaction(migration_root)
    assert selected["transaction"]["transaction_id"] == "good"


def test_choose_qfx_transaction_skips_newer_stale_plan_lineage(tmp_path, monkeypatch):
    migration_root = tmp_path / "migrations" / "sw1203"
    current_digest = "a" * 64
    stale_digest = "b" * 64
    _write_qfx_plan(migration_root, "plan-current", current_digest)
    _write_qfx_plan(migration_root, "plan-stale", stale_digest)
    _write_qfx_transaction(
        migration_root,
        "tx-current",
        "plan-current",
        "2026-09-08T18:00:00Z",
    )
    _write_qfx_transaction(
        migration_root,
        "tx-stale-newer",
        "plan-stale",
        "2026-09-08T19:00:00Z",
    )

    monkeypatch.setattr(
        "ex_migration_provisioner.inband._current_approved_plan_digest",
        lambda _root: current_digest,
    )
    selected = choose_qfx_transaction(migration_root)
    assert selected["transaction"]["transaction_id"] == "tx-current"

    with pytest.raises(ProvisioningError, match="different approved migration plan"):
        choose_qfx_transaction(migration_root, "tx-stale-newer")


def test_build_validation_binds_environment_without_authorizing_writes():
    identity = {
        "identity_id": "identity-1",
        "observed": {"connection": {"ssh_host_key_sha256": "SHA256:key"}},
    }
    tx = {"transaction_id": "tx-1"}
    profile = {
        "environment": "lab",
        "inband_validation": {"mode": "lab-probe"},
    }
    evidence = {
        "method": "lab-probe",
        "target": {"management_ip": "10.100.163.30", "port": 830},
        "observed_ed25519_fingerprint": "SHA256:key",
        "expected_ed25519_fingerprint": "SHA256:key",
        "fingerprint_match": True,
        "tcp_reachable": True,
        "result": "PASS",
    }
    value = build_validation(
        "sw1203",
        identity,
        sha256_bytes(canonical_bytes(identity)),
        tx,
        "1" * 64,
        profile,
        "2" * 64,
        "3" * 64,
        evidence,
        created_at="2026-09-08T18:00:00Z",
    )
    assert value["result"] == "PASS"
    assert value["inputs"]["environment_profile_digest"] == "2" * 64
    assert value["safety"]["ex4400_writes_authorized"] is False
