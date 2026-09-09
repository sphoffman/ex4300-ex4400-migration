from __future__ import annotations

import ipaddress

from ex_migration_analyzer.core import (
    atomic_json,
    canonical_bytes,
    read_json,
    sha256_bytes,
    sha256_file,
)

from .core import ProvisioningError


MGMT_INSTANCE = "mgmt_junos"


def _require(condition, message):
    if not condition:
        raise ProvisioningError(message)


def recovery_statement(interface, address):
    interface = str(interface or "").strip()
    address = str(address or "").strip()
    _require(interface, "old-switch recovery management interface is required")
    _require(address, "old-switch recovery address is required")
    return "set interfaces %s unit 0 family inet address %s" % (interface, address)


def recovery_statements(interface, address, gateway, routing_instance=MGMT_INSTANCE):
    interface = str(interface or "").strip()
    routing_instance = str(routing_instance or "").strip()
    _require(interface, "old-switch recovery management interface is required")
    _require(routing_instance == MGMT_INSTANCE, "old-switch recovery must use mgmt_junos")
    try:
        recovery = ipaddress.ip_interface(str(address))
        next_hop = ipaddress.ip_address(str(gateway))
    except ValueError as exc:
        raise ProvisioningError("invalid old-switch OOB recovery addressing: %s" % exc)
    _require(recovery.version == 4 and next_hop.version == 4, "old-switch OOB recovery must use IPv4")
    _require(next_hop in recovery.network, "old-switch OOB gateway is not on the recovery subnet")
    _require(next_hop != recovery.ip, "old-switch OOB gateway cannot equal the recovery IP")
    return [
        "set system management-instance",
        recovery_statement(interface, str(recovery)),
        "set routing-instances %s routing-options static route 0.0.0.0/0 next-hop %s"
        % (routing_instance, next_hop),
    ]


def build_recovery_transaction(
    migration_id,
    plan,
    plan_digest,
    plan_approval_digest,
    environment,
    source_logical_address,
    source_transport_address,
    recovery_interface,
    recovery_address,
    recovery_gateway,
    source_ssh_host_key_sha256,
    candidate_diff,
    approved_at,
    confirm_minutes,
    bootstrap_identity_id=None,
    bootstrap_identity_digest=None,
    bootstrap_profile_digest=None,
    master_defaults_before=None,
):
    diff_digest = sha256_bytes(str(candidate_diff or "").encode("utf-8"))
    key = {
        "migration_id": migration_id,
        "plan_digest": plan_digest,
        "bootstrap_identity_digest": bootstrap_identity_digest,
        "recovery_interface": recovery_interface,
        "recovery_address": recovery_address,
        "recovery_gateway": recovery_gateway,
        "candidate_diff_sha256": diff_digest,
    }
    transaction_id = sha256_bytes(canonical_bytes(key))[:16]
    expected_hostname = str(plan.get("template_variables", {}).get("old_hostname") or "")
    return {
        "schema_version": "1.3",
        "transaction_id": transaction_id,
        "migration_id": migration_id,
        "approved_at": approved_at,
        "confirm_minutes": int(confirm_minutes),
        "inputs": {
            "plan_id": plan.get("plan_id"),
            "plan_digest": plan_digest,
            "plan_approval_digest": plan_approval_digest,
            "bootstrap_identity_id": bootstrap_identity_id,
            "bootstrap_identity_digest": bootstrap_identity_digest,
            "bootstrap_profile_digest": bootstrap_profile_digest,
        },
        "environment": environment,
        "source_identity": {
            "configured_hostname": expected_hostname,
        },
        "source_access": {
            "logical_address": source_logical_address,
            "transport_address": source_transport_address,
        },
        "recovery": {
            "routing_instance": MGMT_INSTANCE,
            "interface": recovery_interface,
            "address": recovery_address,
            "gateway": recovery_gateway,
            "logical_address": str(ipaddress.ip_interface(str(recovery_address)).ip),
        },
        "source_ssh_host_key_sha256": source_ssh_host_key_sha256,
        "candidate_diff_sha256": diff_digest,
        "master_defaults_before": sorted(master_defaults_before or []),
        "commit": {
            "status": "APPROVED_PENDING_COMMIT",
            "confirmed": False,
        },
        "validation": {
            "result": "PENDING",
            "checks": [],
            "recovery_path_verified": False,
        },
        "safety": {
            "duplicate_bootstrap_ip_requires_physical_l2_isolation_until_cable_move": True,
            "replacement_may_still_own_bootstrap_ip_before_cutover": True,
            "existing_inband_management_preserved": True,
            "master_routing_table_default_unchanged": True,
            "dedicated_management_instance_required": True,
            "commit_confirmed_required": True,
            "post_cable_recovery_verification_required": True,
            "same_ssh_host_key_required_after_cable_move": True,
            "same_configured_hostname_required_after_cable_move": True,
        },
    }


def persist_recovery_transaction(migration_root, transaction, candidate_diff):
    destination = migration_root / "old-switch" / "recovery-transactions" / transaction["transaction_id"]
    destination.mkdir(parents=True, exist_ok=True)
    tx_path = destination / "transaction.json"
    diff_path = destination / "candidate.diff"
    normalized = str(candidate_diff or "")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    if diff_path.exists():
        _require(diff_path.read_text(encoding="utf-8") == normalized, "old-switch recovery candidate diff changed")
    else:
        diff_path.write_text(normalized, encoding="utf-8")
    atomic_json(tx_path, transaction)
    atomic_json(destination / "integrity.json", {
        "transaction.json": sha256_file(tx_path),
        "candidate.diff": sha256_file(diff_path),
    })
    return destination


def validate_existing_recovery_transaction(directory, migration_id, require_committed=False):
    tx_path = directory / "transaction.json"
    diff_path = directory / "candidate.diff"
    integrity_path = directory / "integrity.json"
    _require(tx_path.is_file() and diff_path.is_file() and integrity_path.is_file(), "incomplete old-switch recovery transaction")
    integrity = read_json(integrity_path)
    _require(integrity.get("transaction.json") == sha256_file(tx_path), "old-switch recovery transaction integrity failed")
    _require(integrity.get("candidate.diff") == sha256_file(diff_path), "old-switch recovery diff integrity failed")
    transaction = read_json(tx_path)
    _require(transaction.get("migration_id") == migration_id, "old-switch recovery migration ID mismatch")
    if require_committed:
        _require(transaction.get("commit", {}).get("status") == "COMMITTED_AND_CONFIRMED", "old-switch recovery transaction is not committed and confirmed")
        _require(transaction.get("commit", {}).get("confirmed") is True, "old-switch recovery final confirmation is missing")
        _require(transaction.get("validation", {}).get("result") == "PASS", "old-switch recovery pre-cutover validation did not pass")
    return {
        "transaction": transaction,
        "transaction_path": tx_path,
        "transaction_digest": sha256_file(tx_path),
        "directory": directory,
    }


def choose_recovery_transaction(migration_root, transaction_id=None):
    root = migration_root / "old-switch" / "recovery-transactions"
    if transaction_id:
        directory = root / str(transaction_id)
        _require(directory.is_dir(), "old-switch recovery transaction %s was not found" % transaction_id)
        return validate_existing_recovery_transaction(directory, migration_root.name, require_committed=True)
    candidates = []
    if root.is_dir():
        for directory in root.iterdir():
            if not directory.is_dir():
                continue
            try:
                selected = validate_existing_recovery_transaction(directory, migration_root.name, require_committed=True)
            except ProvisioningError:
                continue
            tx = selected["transaction"]
            stamp = str(tx.get("commit", {}).get("confirmed_at") or tx.get("approved_at") or "")
            candidates.append((stamp, str(tx.get("transaction_id") or directory.name), selected))
    _require(candidates, "no integrity-valid committed-and-confirmed old-switch recovery transaction was found")
    candidates.sort(reverse=True, key=lambda item: (item[0], item[1]))
    return candidates[0][2]


def build_recovery_verification(transaction, transaction_digest, observed_hostname, ssh_host_key_sha256, config_sha256, verified_at):
    key = {
        "migration_id": transaction.get("migration_id"),
        "recovery_transaction_id": transaction.get("transaction_id"),
        "recovery_transaction_digest": transaction_digest,
        "observed_hostname": observed_hostname,
        "ssh_host_key_sha256": ssh_host_key_sha256,
        "config_sha256": config_sha256,
    }
    verification_id = sha256_bytes(canonical_bytes(key))[:16]
    return {
        "schema_version": "1.0",
        "verification_id": verification_id,
        "migration_id": transaction.get("migration_id"),
        "verified_at": verified_at,
        "inputs": {
            "recovery_transaction_id": transaction.get("transaction_id"),
            "recovery_transaction_digest": transaction_digest,
        },
        "observed": {
            "hostname": observed_hostname,
            "ssh_host_key_sha256": ssh_host_key_sha256,
            "configuration_sha256": config_sha256,
        },
        "result": "PASS",
        "checks": [
            "RECOVERY_SSH_HOST_KEY_MATCH",
            "APPROVED_SOURCE_HOSTNAME_MATCH",
            "MGMT_JUNOS_ENABLED",
            "RECOVERY_CONFIGURATION_PRESENT",
            "MGMT_JUNOS_DEFAULT_PRESENT",
            "MASTER_DEFAULT_ROUTE_UNCHANGED",
        ],
    }


def persist_recovery_verification(migration_root, verification):
    destination = migration_root / "old-switch" / "recovery-verifications" / verification["verification_id"]
    path = destination / "verification.json"
    if path.is_file():
        integrity = read_json(destination / "integrity.json")
        _require(integrity.get("verification.json") == sha256_file(path), "old-switch recovery verification integrity failed")
        existing = read_json(path)
        comparable_existing = dict(existing)
        comparable_new = dict(verification)
        comparable_existing.pop("verified_at", None)
        comparable_new.pop("verified_at", None)
        _require(comparable_existing == comparable_new, "existing recovery verification ID has different content")
        return destination, existing, "UNCHANGED"
    destination.mkdir(parents=True, exist_ok=False)
    atomic_json(path, verification)
    atomic_json(destination / "integrity.json", {"verification.json": sha256_file(path)})
    return destination, verification, "CREATED"
