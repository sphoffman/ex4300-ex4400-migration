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
    """Backward-compatible helper for the VME address statement only."""
    interface = str(interface or "").strip()
    address = str(address or "").strip()
    _require(interface, "old-switch recovery management interface is required")
    _require(address, "old-switch recovery address is required")
    return "set interfaces %s unit 0 family inet address %s" % (interface, address)


def recovery_statements(interface, address, gateway, routing_instance=MGMT_INSTANCE):
    """Build the complete isolated OOB recovery intent.

    Junos reserves ``mgmt_junos`` for the dedicated management instance. Enabling
    ``system management-instance`` moves the supported management interface (VME
    for an EX4300 Virtual Chassis) out of the master routing table. The recovery
    default therefore belongs only in ``mgmt_junos``.
    """
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
    recovery_transport_address,
    source_ssh_host_key_sha256,
    candidate_diff,
    approved_at,
    confirm_minutes,
    path_proof_mode,
    bootstrap_identity_id=None,
    bootstrap_identity_digest=None,
    bootstrap_profile_digest=None,
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
    return {
        "schema_version": "1.1",
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
        "source_access": {
            "logical_address": source_logical_address,
            "transport_address": source_transport_address,
        },
        "recovery": {
            "routing_instance": MGMT_INSTANCE,
            "interface": recovery_interface,
            "address": recovery_address,
            "gateway": recovery_gateway,
            "transport_address": recovery_transport_address,
            "path_proof_mode": path_proof_mode,
        },
        "source_ssh_host_key_sha256": source_ssh_host_key_sha256,
        "recovery_ssh_host_key_sha256": None,
        "candidate_diff_sha256": diff_digest,
        "commit": {
            "status": "APPROVED_PENDING_COMMIT",
            "confirmed": False,
        },
        "validation": {
            "result": "PENDING",
            "checks": [],
        },
        "safety": {
            "bootstrap_oob_address_released_by_replacement_acknowledged": True,
            "existing_inband_management_preserved": True,
            "master_routing_table_default_unchanged": True,
            "dedicated_management_instance_required": True,
            "commit_confirmed_required": True,
            "secondary_recovery_connection_required": True,
            "same_ssh_host_key_required": True,
            "same_configured_hostname_required": True,
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


def validate_existing_recovery_transaction(directory, migration_id):
    tx_path = directory / "transaction.json"
    diff_path = directory / "candidate.diff"
    integrity_path = directory / "integrity.json"
    _require(tx_path.is_file() and diff_path.is_file() and integrity_path.is_file(), "incomplete old-switch recovery transaction")
    integrity = read_json(integrity_path)
    _require(integrity.get("transaction.json") == sha256_file(tx_path), "old-switch recovery transaction integrity failed")
    _require(integrity.get("candidate.diff") == sha256_file(diff_path), "old-switch recovery diff integrity failed")
    transaction = read_json(tx_path)
    _require(transaction.get("migration_id") == migration_id, "old-switch recovery migration ID mismatch")
    return transaction
